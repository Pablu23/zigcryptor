const std = @import("std");
const crypto = std.crypto;

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    const stdin = std.io.getStdIn().reader();
    var buf: [50]u8 = std.mem.zeroes([50]u8);
    std.debug.print("Password: ", .{});
    const input = try stdin.readUntilDelimiterOrEof(buf[0..], '\n') orelse return;
    const pwd = std.mem.trimRight(u8, input[0 .. input.len - 1], "\r");

    var should_encrypt = false;
    var args = try std.process.argsWithAllocator(allocator);

    _ = args.skip();
    const dir = std.fs.cwd();
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "encrypt")) {
            should_encrypt = true;
        } else if (std.mem.eql(u8, arg, "decrypt")) {
            should_encrypt = false;
        } else {
            if (should_encrypt) {
                var key: [32]u8 = std.mem.zeroes([32]u8);
                var nonce: [24]u8 = undefined;
                crypto.random.bytes(&nonce);
                try crypto.pwhash.argon2.kdf(allocator, &key, pwd, &nonce, crypto.pwhash.argon2.Params.interactive_2id, crypto.pwhash.argon2.Mode.argon2id);
                try encrypt(dir, arg, key, nonce);
            } else {
                try decrypt(allocator, dir, arg, pwd);
            }
        }
    }
}

pub fn decrypt(allocator: std.mem.Allocator, dir: std.fs.Dir, path: []const u8, pwd: []const u8) !void {
    {
        var out_buf: [512]u8 = undefined;
        var in_buf: [512]u8 = undefined;
        var nonce: [24]u8 = undefined;
        var key: [32]u8 = undefined;

        var file = try dir.openFile(path, .{ .mode = .read_only });
        defer file.close();

        const end_pos = try file.getEndPos();
        const rread = try file.pread(&nonce, end_pos - 24);
        std.debug.print("Read: {}\nHex: {x}\n", .{ rread, nonce[0..] });

        try crypto.pwhash.argon2.kdf(allocator, &key, pwd, &nonce, crypto.pwhash.argon2.Params.interactive_2id, crypto.pwhash.argon2.Mode.argon2id);
        var out_file = try dir.createFile(path[0 .. path.len - 4], .{
            .read = true,
            .truncate = true,
        });
        defer out_file.close();

        var counter: u32 = 0;
        var read: usize = 0;
        var offset: usize = 0;
        while (true) {
            read = try file.pread(&in_buf, offset);
            if (read <= 0 or offset >= (end_pos - 24)) {
                break;
            }

            if (offset + 512 >= end_pos - 24) {
                read -= 24;
            }

            crypto.stream.chacha.XChaCha20IETF.xor(out_buf[0..read], in_buf[0..read], counter, key, nonce);
            counter += 1;
            _ = try out_file.pwrite(out_buf[0..read], offset);
            offset += read;
        }
    }
    try dir.deleteFile(path);
}

pub fn encrypt(dir: std.fs.Dir, path: []const u8, key: [32]u8, nonce: [24]u8) !void {
    {
        var file = try dir.openFile(path, .{ .mode = .read_write });
        defer file.close();
        var out_buf: [512]u8 = undefined;
        var in_buf: [512]u8 = undefined;

        var counter: u32 = 0;
        var read: usize = 0;
        var offset: usize = 0;
        while (true) {
            read = try file.pread(&in_buf, offset);
            if (read <= 0) {
                break;
            }

            crypto.stream.chacha.XChaCha20IETF.xor(out_buf[0..read], in_buf[0..read], counter, key, nonce);
            counter += 1;
            _ = try file.pwrite(out_buf[0..read], offset);
            offset += read;
        }

        const wrote = try file.pwrite(&nonce, offset);
        std.debug.print("Wrote: {} bytes\nHex: {x}\n", .{ wrote, nonce[0..] });
    }
}

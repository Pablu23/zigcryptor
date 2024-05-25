const std = @import("std");
const crypto = std.crypto;

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    const stdin = std.io.getStdIn().reader();
    var buf: [50]u8 = std.mem.zeroes([50]u8);
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

        var file = try dir.openFile(path, .{});
        defer file.close();

        _ = try file.read(&nonce);

        try crypto.pwhash.argon2.kdf(allocator, &key, pwd, &nonce, crypto.pwhash.argon2.Params.interactive_2id, crypto.pwhash.argon2.Mode.argon2id);
        var out_file = try dir.createFile(path[0 .. path.len - 4], .{
            .read = true,
            .truncate = true,
        });
        defer out_file.close();

        var counter: u32 = 0;
        var read: usize = 0;
        while (true) {
            read = try file.read(&in_buf);
            if (read <= 0) {
                break;
            }

            crypto.stream.chacha.XChaCha20IETF.xor(out_buf[0..read], in_buf[0..read], counter, key, nonce);
            counter += 1;
            _ = try out_file.write(out_buf[0..read]);
        }
    }
    try dir.deleteFile(path);
}

pub fn encrypt(dir: std.fs.Dir, path: []const u8, key: [32]u8, nonce: [24]u8) !void {
    {
        var file = try dir.openFile(path, .{});
        defer file.close();
        var out_buf: [512]u8 = undefined;
        var in_buf: [512]u8 = undefined;

        // missuse out_buf as buffer for format string
        _ = try std.fmt.bufPrint(out_buf[0 .. path.len + 4], "{s}.cha", .{path});
        var out_file = try dir.createFile(out_buf[0 .. path.len + 4], .{
            .read = true,
        });
        defer out_file.close();

        _ = try out_file.write(&nonce);

        var counter: u32 = 0;
        var read: usize = 0;
        while (true) {
            read = try file.read(&in_buf);
            if (read <= 0) {
                break;
            }

            crypto.stream.chacha.XChaCha20IETF.xor(out_buf[0..read], in_buf[0..read], counter, key, nonce);
            counter += 1;
            _ = try out_file.write(out_buf[0..read]);
        }
    }
    try dir.deleteFile(path);
}

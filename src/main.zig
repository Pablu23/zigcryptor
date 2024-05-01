const std = @import("std");
const crypto = std.crypto;

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    const pwd = "Test123!";

    var key: [32]u8 = std.mem.zeroes([32]u8);
    var nonce: [24]u8 = undefined;

    crypto.random.bytes(&nonce);

    try crypto.pwhash.argon2.kdf(allocator, &key, pwd, &nonce, crypto.pwhash.argon2.Params.interactive_2id, crypto.pwhash.argon2.Mode.argon2id);
    try encrypt("test.txt", key, nonce);
    try decrypt(allocator, "test.txt.cha", pwd[0..]);
}

pub fn decrypt(allocator: std.mem.Allocator, path: []const u8, pwd: []const u8) !void {
    {
        var out_buf: [512]u8 = undefined;
        var in_buf: [512]u8 = undefined;
        var nonce: [24]u8 = undefined;
        var key: [32]u8 = undefined;

        var file = try std.fs.cwd().openFile(path, .{});
        defer file.close();

        _ = try file.read(&nonce);

        try crypto.pwhash.argon2.kdf(allocator, &key, pwd, &nonce, crypto.pwhash.argon2.Params.interactive_2id, crypto.pwhash.argon2.Mode.argon2id);
        var out_file = try std.fs.cwd().createFile(path[0 .. path.len - 4], .{
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
    try std.fs.cwd().deleteFile(path);
}

pub fn encrypt(path: []const u8, key: [32]u8, nonce: [24]u8) !void {
    {
        var file = try std.fs.cwd().openFile(path, .{});
        defer file.close();
        var out_buf: [512]u8 = undefined;
        var in_buf: [512]u8 = undefined;

        // missuse out_buf as buffer for format string
        _ = try std.fmt.bufPrint(out_buf[0 .. path.len + 4], "{s}.cha", .{path});
        var out_file = try std.fs.cwd().createFile(out_buf[0 .. path.len + 4], .{
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
    try std.fs.cwd().deleteFile(path);
}

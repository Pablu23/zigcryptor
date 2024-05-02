const std = @import("std");
const crypto = std.crypto;

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    const pwd = "Test123!";

    const dir = try std.fs.cwd().openDir("./test", .{ .iterate = true });
    if (dir.openDir("private", .{ .iterate = true })) |priv| {
        var walker = try priv.walk(allocator);
        defer walker.deinit();

        while (try walker.next()) |f| {
            if (f.kind == std.fs.Dir.Entry.Kind.file) {
                decrypt(allocator, priv, f.path, pwd) catch |err| std.debug.print("{?}\n", .{err});
            }
        }

        try dir.deleteDir("private");
    } else |err| switch (err) {
        std.fs.Dir.OpenError.FileNotFound => {
            var key: [32]u8 = std.mem.zeroes([32]u8);
            var nonce: [24]u8 = undefined;
            crypto.random.bytes(&nonce);
            try crypto.pwhash.argon2.kdf(allocator, &key, pwd, &nonce, crypto.pwhash.argon2.Params.interactive_2id, crypto.pwhash.argon2.Mode.argon2id);

            try dir.makeDir("private");

            var walker = try dir.walk(allocator);
            defer walker.deinit();

            while (try walker.next()) |f| {
                if (f.kind == std.fs.Dir.Entry.Kind.file) {
                    std.debug.print("Encrypting {s}\n", .{f.path});
                    encrypt(dir, f.path, key, nonce) catch |e| std.debug.print("{?}\n", .{e});
                }
            }
        },
        else => {
            std.debug.print("Err: {?}\n", .{err});
            return;
        },
    }
}

pub fn decrypt(allocator: std.mem.Allocator, priv: std.fs.Dir, path: []const u8, pwd: []const u8) !void {
    {
        var out_buf: [512]u8 = undefined;
        var in_buf: [512]u8 = undefined;
        var nonce: [24]u8 = undefined;
        var key: [32]u8 = undefined;

        var file = try priv.openFile(path, .{});
        defer file.close();

        _ = try file.read(&nonce);
        var dir = try priv.openDir("..", .{});

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
    try priv.deleteFile(path);
}

pub fn encrypt(dir: std.fs.Dir, path: []const u8, key: [32]u8, nonce: [24]u8) !void {
    {
        var file = try dir.openFile(path, .{});
        defer file.close();
        var out_buf: [512]u8 = undefined;
        var in_buf: [512]u8 = undefined;
        var priv = try dir.openDir("private", .{});

        // missuse out_buf as buffer for format string
        _ = try std.fmt.bufPrint(out_buf[0 .. path.len + 4], "{s}.cha", .{path});
        var out_file = try priv.createFile(out_buf[0 .. path.len + 4], .{
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

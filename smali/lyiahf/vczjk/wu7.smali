.class public final Llyiahf/vczjk/wu7;
.super Llyiahf/vczjk/vu7;
.source "SourceFile"


# instance fields
.field public OooO0O0:Llyiahf/vczjk/oz1;

.field public final OooO0OO:Ljava/util/List;

.field public final OooO0Oo:Llyiahf/vczjk/vu7;

.field public final OooO0o:Ljava/lang/String;

.field public final OooO0o0:Ljava/lang/String;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/oz1;Llyiahf/vczjk/vu7;Ljava/lang/String;Ljava/lang/String;)V
    .locals 1

    const-string v0, "configuration"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget v0, p2, Llyiahf/vczjk/vu7;->OooO00o:I

    invoke-direct {p0, v0}, Llyiahf/vczjk/vu7;-><init>(I)V

    iget-object v0, p1, Llyiahf/vczjk/oz1;->OooO0o0:Ljava/util/List;

    iput-object v0, p0, Llyiahf/vczjk/wu7;->OooO0OO:Ljava/util/List;

    iput-object p1, p0, Llyiahf/vczjk/wu7;->OooO0O0:Llyiahf/vczjk/oz1;

    iput-object p2, p0, Llyiahf/vczjk/wu7;->OooO0Oo:Llyiahf/vczjk/vu7;

    iput-object p3, p0, Llyiahf/vczjk/wu7;->OooO0o0:Ljava/lang/String;

    iput-object p4, p0, Llyiahf/vczjk/wu7;->OooO0o:Ljava/lang/String;

    return-void
.end method


# virtual methods
.method public final OooO(Llyiahf/vczjk/zd3;II)V
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/wu7;->OooO0O0:Llyiahf/vczjk/oz1;

    iget-object v1, p0, Llyiahf/vczjk/wu7;->OooO0Oo:Llyiahf/vczjk/vu7;

    if-eqz v0, :cond_2

    iget-object v0, v0, Llyiahf/vczjk/oz1;->OooO0Oo:Llyiahf/vczjk/bh6;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v0, p2, p3}, Llyiahf/vczjk/u34;->OooOOoo(Llyiahf/vczjk/bh6;II)Ljava/util/List;

    move-result-object v0

    if-eqz v0, :cond_2

    invoke-virtual {v1, p1}, Llyiahf/vczjk/vu7;->OooO0oo(Llyiahf/vczjk/zd3;)V

    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p2

    :goto_0
    invoke-interface {p2}, Ljava/util/Iterator;->hasNext()Z

    move-result p3

    if-eqz p3, :cond_0

    invoke-interface {p2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object p3

    check-cast p3, Llyiahf/vczjk/ej5;

    new-instance v0, Llyiahf/vczjk/aa9;

    invoke-direct {v0, p1}, Llyiahf/vczjk/aa9;-><init>(Llyiahf/vczjk/ca9;)V

    invoke-virtual {p3, v0}, Llyiahf/vczjk/ej5;->migrate(Llyiahf/vczjk/j48;)V

    goto :goto_0

    :cond_0
    invoke-virtual {v1, p1}, Llyiahf/vczjk/vu7;->OooOO0(Llyiahf/vczjk/zd3;)Llyiahf/vczjk/pc0;

    move-result-object p2

    iget-boolean p3, p2, Llyiahf/vczjk/pc0;->OooOOO:Z

    if-eqz p3, :cond_1

    const-string p2, "CREATE TABLE IF NOT EXISTS room_master_table (id INTEGER PRIMARY KEY,identity_hash TEXT)"

    invoke-virtual {p1, p2}, Llyiahf/vczjk/zd3;->OooOO0o(Ljava/lang/String;)V

    iget-object p2, p0, Llyiahf/vczjk/wu7;->OooO0o0:Ljava/lang/String;

    new-instance p3, Ljava/lang/StringBuilder;

    const-string v0, "INSERT OR REPLACE INTO room_master_table (id,identity_hash) VALUES(42, \'"

    invoke-direct {p3, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p3, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string p2, "\')"

    invoke-virtual {p3, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p2

    invoke-virtual {p1, p2}, Llyiahf/vczjk/zd3;->OooOO0o(Ljava/lang/String;)V

    return-void

    :cond_1
    new-instance p1, Ljava/lang/IllegalStateException;

    new-instance p3, Ljava/lang/StringBuilder;

    const-string v0, "Migration didn\'t properly handle: "

    invoke-direct {p3, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object p2, p2, Llyiahf/vczjk/pc0;->OooOOOO:Ljava/lang/Object;

    check-cast p2, Ljava/lang/String;

    invoke-virtual {p3, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p2

    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_2
    iget-object v0, p0, Llyiahf/vczjk/wu7;->OooO0O0:Llyiahf/vczjk/oz1;

    if-eqz v0, :cond_a

    invoke-static {v0, p2, p3}, Llyiahf/vczjk/u34;->Oooo0OO(Llyiahf/vczjk/oz1;II)Z

    move-result v2

    if-nez v2, :cond_a

    iget-boolean p2, v0, Llyiahf/vczjk/oz1;->OooOOoo:Z

    if-eqz p2, :cond_7

    new-instance p2, Llyiahf/vczjk/xo8;

    const-string p3, "SELECT name, type FROM sqlite_master WHERE type = \'table\' OR type = \'view\'"

    invoke-direct {p2, p3}, Llyiahf/vczjk/xo8;-><init>(Ljava/lang/String;)V

    invoke-virtual {p1, p2}, Llyiahf/vczjk/zd3;->OoooooO(Llyiahf/vczjk/ia9;)Landroid/database/Cursor;

    move-result-object p2

    :try_start_0
    invoke-static {}, Llyiahf/vczjk/r02;->OooOOO0()Llyiahf/vczjk/y05;

    move-result-object p3

    :cond_3
    :goto_1
    invoke-interface {p2}, Landroid/database/Cursor;->moveToNext()Z

    move-result v0

    const/4 v2, 0x0

    if-eqz v0, :cond_5

    invoke-interface {p2, v2}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    const-string v3, "sqlite_"

    invoke-static {v0, v3, v2}, Llyiahf/vczjk/g79;->Oooo00o(Ljava/lang/String;Ljava/lang/String;Z)Z

    move-result v2

    if-nez v2, :cond_3

    const-string v2, "android_metadata"

    invoke-virtual {v0, v2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_4

    goto :goto_1

    :cond_4
    const/4 v2, 0x1

    invoke-interface {p2, v2}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    move-result-object v2

    const-string v3, "view"

    invoke-static {v2, v3}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v2

    invoke-static {v2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v2

    new-instance v3, Llyiahf/vczjk/xn6;

    invoke-direct {v3, v0, v2}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    invoke-virtual {p3, v3}, Llyiahf/vczjk/y05;->add(Ljava/lang/Object;)Z

    goto :goto_1

    :catchall_0
    move-exception p1

    goto :goto_3

    :cond_5
    invoke-virtual {p3}, Llyiahf/vczjk/y05;->OooOOO0()Llyiahf/vczjk/y05;

    move-result-object p3
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    invoke-interface {p2}, Ljava/io/Closeable;->close()V

    invoke-virtual {p3, v2}, Llyiahf/vczjk/y05;->listIterator(I)Ljava/util/ListIterator;

    move-result-object p2

    :goto_2
    move-object p3, p2

    check-cast p3, Llyiahf/vczjk/co3;

    invoke-virtual {p3}, Llyiahf/vczjk/co3;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_8

    invoke-virtual {p3}, Llyiahf/vczjk/co3;->next()Ljava/lang/Object;

    move-result-object p3

    check-cast p3, Llyiahf/vczjk/xn6;

    invoke-virtual {p3}, Llyiahf/vczjk/xn6;->OooO00o()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/String;

    invoke-virtual {p3}, Llyiahf/vczjk/xn6;->OooO0O0()Ljava/lang/Object;

    move-result-object p3

    check-cast p3, Ljava/lang/Boolean;

    invoke-virtual {p3}, Ljava/lang/Boolean;->booleanValue()Z

    move-result p3

    if-eqz p3, :cond_6

    new-instance p3, Ljava/lang/StringBuilder;

    const-string v2, "DROP VIEW IF EXISTS "

    invoke-direct {p3, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p3

    invoke-virtual {p1, p3}, Llyiahf/vczjk/zd3;->OooOO0o(Ljava/lang/String;)V

    goto :goto_2

    :cond_6
    new-instance p3, Ljava/lang/StringBuilder;

    const-string v2, "DROP TABLE IF EXISTS "

    invoke-direct {p3, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p3

    invoke-virtual {p1, p3}, Llyiahf/vczjk/zd3;->OooOO0o(Ljava/lang/String;)V

    goto :goto_2

    :goto_3
    :try_start_1
    throw p1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    :catchall_1
    move-exception p3

    invoke-static {p2, p1}, Llyiahf/vczjk/rs;->OooOOO(Ljava/io/Closeable;Ljava/lang/Throwable;)V

    throw p3

    :cond_7
    invoke-virtual {v1, p1}, Llyiahf/vczjk/vu7;->OooO0OO(Llyiahf/vczjk/zd3;)V

    :cond_8
    iget-object p2, p0, Llyiahf/vczjk/wu7;->OooO0OO:Ljava/util/List;

    if-eqz p2, :cond_9

    invoke-interface {p2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p2

    :goto_4
    invoke-interface {p2}, Ljava/util/Iterator;->hasNext()Z

    move-result p3

    if-eqz p3, :cond_9

    invoke-interface {p2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object p3

    check-cast p3, Llyiahf/vczjk/lz0;

    invoke-virtual {p3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    goto :goto_4

    :cond_9
    invoke-virtual {v1, p1}, Llyiahf/vczjk/vu7;->OooO00o(Llyiahf/vczjk/zd3;)V

    return-void

    :cond_a
    new-instance p1, Ljava/lang/IllegalStateException;

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "A migration from "

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0, p2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string p2, " to "

    invoke-virtual {v0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0, p3}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string p2, " was required but not found. Please provide the necessary Migration path via RoomDatabase.Builder.addMigration(Migration ...) or allow for destructive migrations via one of the RoomDatabase.Builder.fallbackToDestructiveMigration* methods."

    invoke-virtual {v0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p2

    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public final OooO0Oo(Llyiahf/vczjk/zd3;)V
    .locals 0

    return-void
.end method

.method public final OooO0o(Llyiahf/vczjk/zd3;II)V
    .locals 0

    invoke-virtual {p0, p1, p2, p3}, Llyiahf/vczjk/wu7;->OooO(Llyiahf/vczjk/zd3;II)V

    return-void
.end method

.method public final OooO0o0(Llyiahf/vczjk/zd3;)V
    .locals 4

    new-instance v0, Llyiahf/vczjk/xo8;

    const-string v1, "SELECT count(*) FROM sqlite_master WHERE name != \'android_metadata\'"

    invoke-direct {v0, v1}, Llyiahf/vczjk/xo8;-><init>(Ljava/lang/String;)V

    invoke-virtual {p1, v0}, Llyiahf/vczjk/zd3;->OoooooO(Llyiahf/vczjk/ia9;)Landroid/database/Cursor;

    move-result-object v0

    :try_start_0
    invoke-interface {v0}, Landroid/database/Cursor;->moveToFirst()Z

    move-result v1

    const/4 v2, 0x0

    if-eqz v1, :cond_0

    invoke-interface {v0, v2}, Landroid/database/Cursor;->getInt(I)I

    move-result v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    if-nez v1, :cond_0

    const/4 v2, 0x1

    goto :goto_0

    :catchall_0
    move-exception p1

    goto :goto_3

    :cond_0
    :goto_0
    invoke-interface {v0}, Ljava/io/Closeable;->close()V

    iget-object v0, p0, Llyiahf/vczjk/wu7;->OooO0Oo:Llyiahf/vczjk/vu7;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/vu7;->OooO00o(Llyiahf/vczjk/zd3;)V

    if-nez v2, :cond_2

    invoke-virtual {v0, p1}, Llyiahf/vczjk/vu7;->OooOO0(Llyiahf/vczjk/zd3;)Llyiahf/vczjk/pc0;

    move-result-object v1

    iget-boolean v2, v1, Llyiahf/vczjk/pc0;->OooOOO:Z

    if-eqz v2, :cond_1

    goto :goto_1

    :cond_1
    new-instance p1, Ljava/lang/IllegalStateException;

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v2, "Pre-packaged database has an invalid schema: "

    invoke-direct {v0, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v1, v1, Llyiahf/vczjk/pc0;->OooOOOO:Ljava/lang/Object;

    check-cast v1, Ljava/lang/String;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_2
    :goto_1
    const-string v1, "CREATE TABLE IF NOT EXISTS room_master_table (id INTEGER PRIMARY KEY,identity_hash TEXT)"

    invoke-virtual {p1, v1}, Llyiahf/vczjk/zd3;->OooOO0o(Ljava/lang/String;)V

    iget-object v1, p0, Llyiahf/vczjk/wu7;->OooO0o0:Ljava/lang/String;

    new-instance v2, Ljava/lang/StringBuilder;

    const-string v3, "INSERT OR REPLACE INTO room_master_table (id,identity_hash) VALUES(42, \'"

    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v1, "\')"

    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {p1, v1}, Llyiahf/vczjk/zd3;->OooOO0o(Ljava/lang/String;)V

    invoke-virtual {v0, p1}, Llyiahf/vczjk/vu7;->OooO0o0(Llyiahf/vczjk/zd3;)V

    iget-object p1, p0, Llyiahf/vczjk/wu7;->OooO0OO:Ljava/util/List;

    if-eqz p1, :cond_3

    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :goto_2
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_3

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/lz0;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    goto :goto_2

    :cond_3
    return-void

    :goto_3
    :try_start_1
    throw p1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    :catchall_1
    move-exception v1

    invoke-static {v0, p1}, Llyiahf/vczjk/rs;->OooOOO(Ljava/io/Closeable;Ljava/lang/Throwable;)V

    throw v1
.end method

.method public final OooO0oO(Llyiahf/vczjk/zd3;)V
    .locals 6

    new-instance v0, Llyiahf/vczjk/xo8;

    const-string v1, "SELECT 1 FROM sqlite_master WHERE type = \'table\' AND name=\'room_master_table\'"

    invoke-direct {v0, v1}, Llyiahf/vczjk/xo8;-><init>(Ljava/lang/String;)V

    invoke-virtual {p1, v0}, Llyiahf/vczjk/zd3;->OoooooO(Llyiahf/vczjk/ia9;)Landroid/database/Cursor;

    move-result-object v0

    :try_start_0
    invoke-interface {v0}, Landroid/database/Cursor;->moveToFirst()Z

    move-result v1

    const/4 v2, 0x0

    if-eqz v1, :cond_0

    invoke-interface {v0, v2}, Landroid/database/Cursor;->getInt(I)I

    move-result v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    if-eqz v1, :cond_0

    const/4 v1, 0x1

    goto :goto_0

    :catchall_0
    move-exception p1

    goto/16 :goto_5

    :cond_0
    move v1, v2

    :goto_0
    invoke-interface {v0}, Ljava/io/Closeable;->close()V

    iget-object v0, p0, Llyiahf/vczjk/wu7;->OooO0Oo:Llyiahf/vczjk/vu7;

    iget-object v3, p0, Llyiahf/vczjk/wu7;->OooO0o0:Ljava/lang/String;

    const/4 v4, 0x0

    if-eqz v1, :cond_3

    new-instance v1, Llyiahf/vczjk/xo8;

    const-string v5, "SELECT identity_hash FROM room_master_table WHERE id = 42 LIMIT 1"

    invoke-direct {v1, v5}, Llyiahf/vczjk/xo8;-><init>(Ljava/lang/String;)V

    invoke-virtual {p1, v1}, Llyiahf/vczjk/zd3;->OoooooO(Llyiahf/vczjk/ia9;)Landroid/database/Cursor;

    move-result-object v1

    :try_start_1
    invoke-interface {v1}, Landroid/database/Cursor;->moveToFirst()Z

    move-result v5

    if-eqz v5, :cond_1

    invoke-interface {v1, v2}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    move-result-object v2
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    goto :goto_1

    :catchall_1
    move-exception p1

    goto :goto_2

    :cond_1
    move-object v2, v4

    :goto_1
    invoke-interface {v1}, Ljava/io/Closeable;->close()V

    invoke-virtual {v3, v2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_4

    iget-object v1, p0, Llyiahf/vczjk/wu7;->OooO0o:Ljava/lang/String;

    invoke-virtual {v1, v2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_2

    goto :goto_3

    :cond_2
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "Room cannot verify the data integrity. Looks like you\'ve changed schema but forgot to update the version number. You can simply fix this by increasing the version number. Expected identity hash: "

    const-string v1, ", found: "

    invoke-static {v0, v3, v1, v2}, Llyiahf/vczjk/ii5;->OooO(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :goto_2
    :try_start_2
    throw p1
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    :catchall_2
    move-exception v0

    invoke-static {v1, p1}, Llyiahf/vczjk/rs;->OooOOO(Ljava/io/Closeable;Ljava/lang/Throwable;)V

    throw v0

    :cond_3
    invoke-virtual {v0, p1}, Llyiahf/vczjk/vu7;->OooOO0(Llyiahf/vczjk/zd3;)Llyiahf/vczjk/pc0;

    move-result-object v1

    iget-boolean v2, v1, Llyiahf/vczjk/pc0;->OooOOO:Z

    if-eqz v2, :cond_6

    const-string v1, "CREATE TABLE IF NOT EXISTS room_master_table (id INTEGER PRIMARY KEY,identity_hash TEXT)"

    invoke-virtual {p1, v1}, Llyiahf/vczjk/zd3;->OooOO0o(Ljava/lang/String;)V

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "INSERT OR REPLACE INTO room_master_table (id,identity_hash) VALUES(42, \'"

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v2, "\')"

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {p1, v1}, Llyiahf/vczjk/zd3;->OooOO0o(Ljava/lang/String;)V

    :cond_4
    :goto_3
    invoke-virtual {v0, p1}, Llyiahf/vczjk/vu7;->OooO0oO(Llyiahf/vczjk/zd3;)V

    iget-object v0, p0, Llyiahf/vczjk/wu7;->OooO0OO:Ljava/util/List;

    if-eqz v0, :cond_5

    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_4
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_5

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/lz0;

    invoke-virtual {v1, p1}, Llyiahf/vczjk/lz0;->OooO00o(Llyiahf/vczjk/ca9;)V

    goto :goto_4

    :cond_5
    iput-object v4, p0, Llyiahf/vczjk/wu7;->OooO0O0:Llyiahf/vczjk/oz1;

    return-void

    :cond_6
    new-instance p1, Ljava/lang/IllegalStateException;

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v2, "Pre-packaged database has an invalid schema: "

    invoke-direct {v0, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v1, v1, Llyiahf/vczjk/pc0;->OooOOOO:Ljava/lang/Object;

    check-cast v1, Ljava/lang/String;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :goto_5
    :try_start_3
    throw p1
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_3

    :catchall_3
    move-exception v1

    invoke-static {v0, p1}, Llyiahf/vczjk/rs;->OooOOO(Ljava/io/Closeable;Ljava/lang/Throwable;)V

    throw v1
.end method

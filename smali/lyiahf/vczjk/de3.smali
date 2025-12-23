.class public final Llyiahf/vczjk/de3;
.super Landroid/database/sqlite/SQLiteOpenHelper;
.source "SourceFile"

# interfaces
.implements Ljava/lang/AutoCloseable;


# static fields
.field public static final synthetic OooOo00:I


# instance fields
.field public final OooOOO:Llyiahf/vczjk/uz5;

.field public final OooOOO0:Landroid/content/Context;

.field public final OooOOOO:Llyiahf/vczjk/vu7;

.field public final OooOOOo:Z

.field public final OooOOo:Llyiahf/vczjk/g57;

.field public OooOOo0:Z

.field public OooOOoo:Z


# direct methods
.method public constructor <init>(Landroid/content/Context;Ljava/lang/String;Llyiahf/vczjk/uz5;Llyiahf/vczjk/vu7;Z)V
    .locals 7

    const-string v0, "context"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "callback"

    invoke-static {p4, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v6, Llyiahf/vczjk/ae3;

    invoke-direct {v6, p4, p3}, Llyiahf/vczjk/ae3;-><init>(Llyiahf/vczjk/vu7;Llyiahf/vczjk/uz5;)V

    const/4 v4, 0x0

    iget v5, p4, Llyiahf/vczjk/vu7;->OooO00o:I

    move-object v1, p0

    move-object v2, p1

    move-object v3, p2

    invoke-direct/range {v1 .. v6}, Landroid/database/sqlite/SQLiteOpenHelper;-><init>(Landroid/content/Context;Ljava/lang/String;Landroid/database/sqlite/SQLiteDatabase$CursorFactory;ILandroid/database/DatabaseErrorHandler;)V

    iput-object v2, v1, Llyiahf/vczjk/de3;->OooOOO0:Landroid/content/Context;

    iput-object p3, v1, Llyiahf/vczjk/de3;->OooOOO:Llyiahf/vczjk/uz5;

    iput-object p4, v1, Llyiahf/vczjk/de3;->OooOOOO:Llyiahf/vczjk/vu7;

    iput-boolean p5, v1, Llyiahf/vczjk/de3;->OooOOOo:Z

    new-instance p1, Llyiahf/vczjk/g57;

    if-nez v3, :cond_0

    invoke-static {}, Ljava/util/UUID;->randomUUID()Ljava/util/UUID;

    move-result-object p2

    invoke-virtual {p2}, Ljava/util/UUID;->toString()Ljava/lang/String;

    move-result-object p2

    const-string p3, "toString(...)"

    invoke-static {p2, p3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    goto :goto_0

    :cond_0
    move-object p2, v3

    :goto_0
    invoke-virtual {v2}, Landroid/content/Context;->getCacheDir()Ljava/io/File;

    move-result-object p3

    const/4 p4, 0x0

    invoke-direct {p1, p3, p2, p4}, Llyiahf/vczjk/g57;-><init>(Ljava/io/File;Ljava/lang/String;Z)V

    iput-object p1, v1, Llyiahf/vczjk/de3;->OooOOo:Llyiahf/vczjk/g57;

    return-void
.end method


# virtual methods
.method public final OooO0Oo(Z)Llyiahf/vczjk/ca9;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/de3;->OooOOo:Llyiahf/vczjk/g57;

    :try_start_0
    iget-boolean v1, p0, Llyiahf/vczjk/de3;->OooOOoo:Z

    const/4 v2, 0x0

    if-nez v1, :cond_0

    invoke-virtual {p0}, Landroid/database/sqlite/SQLiteOpenHelper;->getDatabaseName()Ljava/lang/String;

    move-result-object v1

    if-eqz v1, :cond_0

    const/4 v1, 0x1

    goto :goto_0

    :catchall_0
    move-exception p1

    goto :goto_1

    :cond_0
    move v1, v2

    :goto_0
    invoke-virtual {v0, v1}, Llyiahf/vczjk/g57;->OooO00o(Z)V

    iput-boolean v2, p0, Llyiahf/vczjk/de3;->OooOOo0:Z

    invoke-virtual {p0, p1}, Llyiahf/vczjk/de3;->OooO0oO(Z)Landroid/database/sqlite/SQLiteDatabase;

    move-result-object v1

    iget-boolean v2, p0, Llyiahf/vczjk/de3;->OooOOo0:Z

    if-eqz v2, :cond_1

    invoke-virtual {p0}, Llyiahf/vczjk/de3;->close()V

    invoke-virtual {p0, p1}, Llyiahf/vczjk/de3;->OooO0Oo(Z)Llyiahf/vczjk/ca9;

    move-result-object p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    invoke-virtual {v0}, Llyiahf/vczjk/g57;->OooO0O0()V

    return-object p1

    :cond_1
    :try_start_1
    iget-object p1, p0, Llyiahf/vczjk/de3;->OooOOO:Llyiahf/vczjk/uz5;

    invoke-static {p1, v1}, Llyiahf/vczjk/mc4;->Oooo0oO(Llyiahf/vczjk/uz5;Landroid/database/sqlite/SQLiteDatabase;)Llyiahf/vczjk/zd3;

    move-result-object p1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    invoke-virtual {v0}, Llyiahf/vczjk/g57;->OooO0O0()V

    return-object p1

    :goto_1
    invoke-virtual {v0}, Llyiahf/vczjk/g57;->OooO0O0()V

    throw p1
.end method

.method public final OooO0oO(Z)Landroid/database/sqlite/SQLiteDatabase;
    .locals 5

    invoke-virtual {p0}, Landroid/database/sqlite/SQLiteOpenHelper;->getDatabaseName()Ljava/lang/String;

    move-result-object v0

    iget-boolean v1, p0, Llyiahf/vczjk/de3;->OooOOoo:Z

    iget-object v2, p0, Llyiahf/vczjk/de3;->OooOOO0:Landroid/content/Context;

    if-eqz v0, :cond_0

    if-nez v1, :cond_0

    invoke-virtual {v2, v0}, Landroid/content/Context;->getDatabasePath(Ljava/lang/String;)Ljava/io/File;

    move-result-object v1

    invoke-virtual {v1}, Ljava/io/File;->getParentFile()Ljava/io/File;

    move-result-object v1

    if-eqz v1, :cond_0

    invoke-virtual {v1}, Ljava/io/File;->mkdirs()Z

    invoke-virtual {v1}, Ljava/io/File;->isDirectory()Z

    move-result v3

    if-nez v3, :cond_0

    new-instance v3, Ljava/lang/StringBuilder;

    const-string v4, "Invalid database parent file, not a directory: "

    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    const-string v3, "SupportSQLite"

    invoke-static {v3, v1}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    :cond_0
    if-eqz p1, :cond_1

    :try_start_0
    invoke-virtual {p0}, Landroid/database/sqlite/SQLiteOpenHelper;->getWritableDatabase()Landroid/database/sqlite/SQLiteDatabase;

    move-result-object v1

    invoke-static {v1}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    return-object v1

    :cond_1
    invoke-virtual {p0}, Landroid/database/sqlite/SQLiteOpenHelper;->getReadableDatabase()Landroid/database/sqlite/SQLiteDatabase;

    move-result-object v1

    invoke-static {v1}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    return-object v1

    :catchall_0
    const-wide/16 v3, 0x1f4

    :try_start_1
    invoke-static {v3, v4}, Ljava/lang/Thread;->sleep(J)V
    :try_end_1
    .catch Ljava/lang/InterruptedException; {:try_start_1 .. :try_end_1} :catch_0

    :catch_0
    if-eqz p1, :cond_2

    :try_start_2
    invoke-virtual {p0}, Landroid/database/sqlite/SQLiteOpenHelper;->getWritableDatabase()Landroid/database/sqlite/SQLiteDatabase;

    move-result-object v1

    invoke-static {v1}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    goto :goto_0

    :catchall_1
    move-exception v1

    goto :goto_1

    :cond_2
    invoke-virtual {p0}, Landroid/database/sqlite/SQLiteOpenHelper;->getReadableDatabase()Landroid/database/sqlite/SQLiteDatabase;

    move-result-object v1

    invoke-static {v1}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    :goto_0
    return-object v1

    :goto_1
    instance-of v3, v1, Llyiahf/vczjk/be3;

    if-eqz v3, :cond_6

    check-cast v1, Llyiahf/vczjk/be3;

    invoke-virtual {v1}, Llyiahf/vczjk/be3;->getCause()Ljava/lang/Throwable;

    move-result-object v3

    invoke-virtual {v1}, Llyiahf/vczjk/be3;->OooO00o()Llyiahf/vczjk/ce3;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    move-result v1

    if-eqz v1, :cond_5

    const/4 v4, 0x1

    if-eq v1, v4, :cond_5

    const/4 v4, 0x2

    if-eq v1, v4, :cond_5

    const/4 v4, 0x3

    if-eq v1, v4, :cond_5

    const/4 v4, 0x4

    if-ne v1, v4, :cond_4

    instance-of v1, v3, Landroid/database/sqlite/SQLiteException;

    if-eqz v1, :cond_3

    move-object v1, v3

    goto :goto_2

    :cond_3
    throw v3

    :cond_4
    new-instance p1, Llyiahf/vczjk/k61;

    invoke-direct {p1}, Ljava/lang/RuntimeException;-><init>()V

    throw p1

    :cond_5
    throw v3

    :cond_6
    :goto_2
    instance-of v3, v1, Landroid/database/sqlite/SQLiteException;

    if-eqz v3, :cond_8

    if-eqz v0, :cond_8

    iget-boolean v3, p0, Llyiahf/vczjk/de3;->OooOOOo:Z

    if-eqz v3, :cond_8

    invoke-virtual {v2, v0}, Landroid/content/Context;->deleteDatabase(Ljava/lang/String;)Z

    if-eqz p1, :cond_7

    :try_start_3
    invoke-virtual {p0}, Landroid/database/sqlite/SQLiteOpenHelper;->getWritableDatabase()Landroid/database/sqlite/SQLiteDatabase;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    goto :goto_3

    :catch_1
    move-exception p1

    goto :goto_4

    :cond_7
    invoke-virtual {p0}, Landroid/database/sqlite/SQLiteOpenHelper;->getReadableDatabase()Landroid/database/sqlite/SQLiteDatabase;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V
    :try_end_3
    .catch Llyiahf/vczjk/be3; {:try_start_3 .. :try_end_3} :catch_1

    :goto_3
    return-object p1

    :goto_4
    invoke-virtual {p1}, Llyiahf/vczjk/be3;->getCause()Ljava/lang/Throwable;

    move-result-object p1

    throw p1

    :cond_8
    throw v1
.end method

.method public final close()V
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/de3;->OooOOo:Llyiahf/vczjk/g57;

    :try_start_0
    iget-boolean v1, v0, Llyiahf/vczjk/g57;->OooO00o:Z

    invoke-virtual {v0, v1}, Llyiahf/vczjk/g57;->OooO00o(Z)V

    invoke-super {p0}, Landroid/database/sqlite/SQLiteOpenHelper;->close()V

    iget-object v1, p0, Llyiahf/vczjk/de3;->OooOOO:Llyiahf/vczjk/uz5;

    const/4 v2, 0x0

    iput-object v2, v1, Llyiahf/vczjk/uz5;->OooOOO:Ljava/lang/Object;

    const/4 v1, 0x0

    iput-boolean v1, p0, Llyiahf/vczjk/de3;->OooOOoo:Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    invoke-virtual {v0}, Llyiahf/vczjk/g57;->OooO0O0()V

    return-void

    :catchall_0
    move-exception v1

    invoke-virtual {v0}, Llyiahf/vczjk/g57;->OooO0O0()V

    throw v1
.end method

.method public final onConfigure(Landroid/database/sqlite/SQLiteDatabase;)V
    .locals 3

    const-string v0, "db"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-boolean v0, p0, Llyiahf/vczjk/de3;->OooOOo0:Z

    iget-object v1, p0, Llyiahf/vczjk/de3;->OooOOOO:Llyiahf/vczjk/vu7;

    if-nez v0, :cond_0

    iget v0, v1, Llyiahf/vczjk/vu7;->OooO00o:I

    invoke-virtual {p1}, Landroid/database/sqlite/SQLiteDatabase;->getVersion()I

    move-result v2

    if-eq v0, v2, :cond_0

    const/4 v0, 0x1

    invoke-virtual {p1, v0}, Landroid/database/sqlite/SQLiteDatabase;->setMaxSqlCacheSize(I)V

    :cond_0
    :try_start_0
    iget-object v0, p0, Llyiahf/vczjk/de3;->OooOOO:Llyiahf/vczjk/uz5;

    invoke-static {v0, p1}, Llyiahf/vczjk/mc4;->Oooo0oO(Llyiahf/vczjk/uz5;Landroid/database/sqlite/SQLiteDatabase;)Llyiahf/vczjk/zd3;

    move-result-object p1

    invoke-virtual {v1, p1}, Llyiahf/vczjk/vu7;->OooO0Oo(Llyiahf/vczjk/zd3;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    return-void

    :catchall_0
    move-exception p1

    new-instance v0, Llyiahf/vczjk/be3;

    sget-object v1, Llyiahf/vczjk/ce3;->OooOOO0:Llyiahf/vczjk/ce3;

    invoke-direct {v0, v1, p1}, Llyiahf/vczjk/be3;-><init>(Llyiahf/vczjk/ce3;Ljava/lang/Throwable;)V

    throw v0
.end method

.method public final onCreate(Landroid/database/sqlite/SQLiteDatabase;)V
    .locals 2

    const-string v0, "sqLiteDatabase"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    :try_start_0
    iget-object v0, p0, Llyiahf/vczjk/de3;->OooOOOO:Llyiahf/vczjk/vu7;

    iget-object v1, p0, Llyiahf/vczjk/de3;->OooOOO:Llyiahf/vczjk/uz5;

    invoke-static {v1, p1}, Llyiahf/vczjk/mc4;->Oooo0oO(Llyiahf/vczjk/uz5;Landroid/database/sqlite/SQLiteDatabase;)Llyiahf/vczjk/zd3;

    move-result-object p1

    invoke-virtual {v0, p1}, Llyiahf/vczjk/vu7;->OooO0o0(Llyiahf/vczjk/zd3;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    return-void

    :catchall_0
    move-exception p1

    new-instance v0, Llyiahf/vczjk/be3;

    sget-object v1, Llyiahf/vczjk/ce3;->OooOOO:Llyiahf/vczjk/ce3;

    invoke-direct {v0, v1, p1}, Llyiahf/vczjk/be3;-><init>(Llyiahf/vczjk/ce3;Ljava/lang/Throwable;)V

    throw v0
.end method

.method public final onDowngrade(Landroid/database/sqlite/SQLiteDatabase;II)V
    .locals 2

    const-string v0, "db"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v0, 0x1

    iput-boolean v0, p0, Llyiahf/vczjk/de3;->OooOOo0:Z

    :try_start_0
    iget-object v0, p0, Llyiahf/vczjk/de3;->OooOOOO:Llyiahf/vczjk/vu7;

    iget-object v1, p0, Llyiahf/vczjk/de3;->OooOOO:Llyiahf/vczjk/uz5;

    invoke-static {v1, p1}, Llyiahf/vczjk/mc4;->Oooo0oO(Llyiahf/vczjk/uz5;Landroid/database/sqlite/SQLiteDatabase;)Llyiahf/vczjk/zd3;

    move-result-object p1

    invoke-virtual {v0, p1, p2, p3}, Llyiahf/vczjk/vu7;->OooO0o(Llyiahf/vczjk/zd3;II)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    return-void

    :catchall_0
    move-exception p1

    new-instance p2, Llyiahf/vczjk/be3;

    sget-object p3, Llyiahf/vczjk/ce3;->OooOOOo:Llyiahf/vczjk/ce3;

    invoke-direct {p2, p3, p1}, Llyiahf/vczjk/be3;-><init>(Llyiahf/vczjk/ce3;Ljava/lang/Throwable;)V

    throw p2
.end method

.method public final onOpen(Landroid/database/sqlite/SQLiteDatabase;)V
    .locals 2

    const-string v0, "db"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-boolean v0, p0, Llyiahf/vczjk/de3;->OooOOo0:Z

    if-nez v0, :cond_0

    :try_start_0
    iget-object v0, p0, Llyiahf/vczjk/de3;->OooOOOO:Llyiahf/vczjk/vu7;

    iget-object v1, p0, Llyiahf/vczjk/de3;->OooOOO:Llyiahf/vczjk/uz5;

    invoke-static {v1, p1}, Llyiahf/vczjk/mc4;->Oooo0oO(Llyiahf/vczjk/uz5;Landroid/database/sqlite/SQLiteDatabase;)Llyiahf/vczjk/zd3;

    move-result-object p1

    invoke-virtual {v0, p1}, Llyiahf/vczjk/vu7;->OooO0oO(Llyiahf/vczjk/zd3;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_0

    :catchall_0
    move-exception p1

    new-instance v0, Llyiahf/vczjk/be3;

    sget-object v1, Llyiahf/vczjk/ce3;->OooOOo0:Llyiahf/vczjk/ce3;

    invoke-direct {v0, v1, p1}, Llyiahf/vczjk/be3;-><init>(Llyiahf/vczjk/ce3;Ljava/lang/Throwable;)V

    throw v0

    :cond_0
    :goto_0
    const/4 p1, 0x1

    iput-boolean p1, p0, Llyiahf/vczjk/de3;->OooOOoo:Z

    return-void
.end method

.method public final onUpgrade(Landroid/database/sqlite/SQLiteDatabase;II)V
    .locals 2

    const-string v0, "sqLiteDatabase"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v0, 0x1

    iput-boolean v0, p0, Llyiahf/vczjk/de3;->OooOOo0:Z

    :try_start_0
    iget-object v0, p0, Llyiahf/vczjk/de3;->OooOOOO:Llyiahf/vczjk/vu7;

    iget-object v1, p0, Llyiahf/vczjk/de3;->OooOOO:Llyiahf/vczjk/uz5;

    invoke-static {v1, p1}, Llyiahf/vczjk/mc4;->Oooo0oO(Llyiahf/vczjk/uz5;Landroid/database/sqlite/SQLiteDatabase;)Llyiahf/vczjk/zd3;

    move-result-object p1

    invoke-virtual {v0, p1, p2, p3}, Llyiahf/vczjk/vu7;->OooO(Llyiahf/vczjk/zd3;II)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    return-void

    :catchall_0
    move-exception p1

    new-instance p2, Llyiahf/vczjk/be3;

    sget-object p3, Llyiahf/vczjk/ce3;->OooOOOO:Llyiahf/vczjk/ce3;

    invoke-direct {p2, p3, p1}, Llyiahf/vczjk/be3;-><init>(Llyiahf/vczjk/ce3;Ljava/lang/Throwable;)V

    throw p2
.end method

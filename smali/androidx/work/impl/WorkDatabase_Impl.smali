.class public final Landroidx/work/impl/WorkDatabase_Impl;
.super Landroidx/work/impl/WorkDatabase;
.source "SourceFile"


# instance fields
.field public volatile OooO00o:Llyiahf/vczjk/bra;

.field public volatile OooO0O0:Llyiahf/vczjk/n62;

.field public volatile OooO0OO:Llyiahf/vczjk/era;

.field public volatile OooO0Oo:Llyiahf/vczjk/ld9;

.field public volatile OooO0o:Llyiahf/vczjk/uqa;

.field public volatile OooO0o0:Llyiahf/vczjk/tqa;

.field public volatile OooO0oO:Llyiahf/vczjk/a27;

.field public volatile OooO0oo:Llyiahf/vczjk/tg7;


# direct methods
.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Landroidx/work/impl/WorkDatabase;-><init>()V

    return-void
.end method

.method public static synthetic OooOO0(Landroidx/work/impl/WorkDatabase_Impl;)Ljava/util/List;
    .locals 0

    iget-object p0, p0, Llyiahf/vczjk/ru7;->mCallbacks:Ljava/util/List;

    return-object p0
.end method

.method public static synthetic OooOO0O(Landroidx/work/impl/WorkDatabase_Impl;)Ljava/util/List;
    .locals 0

    iget-object p0, p0, Llyiahf/vczjk/ru7;->mCallbacks:Ljava/util/List;

    return-object p0
.end method

.method public static synthetic OooOO0o(Landroidx/work/impl/WorkDatabase_Impl;Llyiahf/vczjk/zd3;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ru7;->mDatabase:Llyiahf/vczjk/ca9;

    return-void
.end method

.method public static synthetic OooOOO0(Landroidx/work/impl/WorkDatabase_Impl;)Ljava/util/List;
    .locals 0

    iget-object p0, p0, Llyiahf/vczjk/ru7;->mCallbacks:Ljava/util/List;

    return-object p0
.end method


# virtual methods
.method public final OooO()Llyiahf/vczjk/era;
    .locals 3

    iget-object v0, p0, Landroidx/work/impl/WorkDatabase_Impl;->OooO0OO:Llyiahf/vczjk/era;

    if-eqz v0, :cond_0

    iget-object v0, p0, Landroidx/work/impl/WorkDatabase_Impl;->OooO0OO:Llyiahf/vczjk/era;

    return-object v0

    :cond_0
    monitor-enter p0

    :try_start_0
    iget-object v0, p0, Landroidx/work/impl/WorkDatabase_Impl;->OooO0OO:Llyiahf/vczjk/era;

    if-nez v0, :cond_1

    new-instance v0, Llyiahf/vczjk/era;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    iput-object p0, v0, Llyiahf/vczjk/era;->OooOOO0:Ljava/lang/Object;

    new-instance v1, Llyiahf/vczjk/m62;

    const/4 v2, 0x7

    invoke-direct {v1, p0, v2}, Llyiahf/vczjk/m62;-><init>(Llyiahf/vczjk/ru7;I)V

    iput-object v1, v0, Llyiahf/vczjk/era;->OooOOO:Ljava/lang/Object;

    new-instance v1, Llyiahf/vczjk/qw7;

    const/16 v2, 0x15

    invoke-direct {v1, p0, v2}, Llyiahf/vczjk/qw7;-><init>(Llyiahf/vczjk/ru7;I)V

    iput-object v0, p0, Landroidx/work/impl/WorkDatabase_Impl;->OooO0OO:Llyiahf/vczjk/era;

    goto :goto_0

    :catchall_0
    move-exception v0

    goto :goto_1

    :cond_1
    :goto_0
    iget-object v0, p0, Landroidx/work/impl/WorkDatabase_Impl;->OooO0OO:Llyiahf/vczjk/era;

    monitor-exit p0

    return-object v0

    :goto_1
    monitor-exit p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    throw v0
.end method

.method public final OooO0O0()Llyiahf/vczjk/n62;
    .locals 1

    iget-object v0, p0, Landroidx/work/impl/WorkDatabase_Impl;->OooO0O0:Llyiahf/vczjk/n62;

    if-eqz v0, :cond_0

    iget-object v0, p0, Landroidx/work/impl/WorkDatabase_Impl;->OooO0O0:Llyiahf/vczjk/n62;

    return-object v0

    :cond_0
    monitor-enter p0

    :try_start_0
    iget-object v0, p0, Landroidx/work/impl/WorkDatabase_Impl;->OooO0O0:Llyiahf/vczjk/n62;

    if-nez v0, :cond_1

    new-instance v0, Llyiahf/vczjk/n62;

    invoke-direct {v0, p0}, Llyiahf/vczjk/n62;-><init>(Landroidx/work/impl/WorkDatabase_Impl;)V

    iput-object v0, p0, Landroidx/work/impl/WorkDatabase_Impl;->OooO0O0:Llyiahf/vczjk/n62;

    goto :goto_0

    :catchall_0
    move-exception v0

    goto :goto_1

    :cond_1
    :goto_0
    iget-object v0, p0, Landroidx/work/impl/WorkDatabase_Impl;->OooO0O0:Llyiahf/vczjk/n62;

    monitor-exit p0

    return-object v0

    :goto_1
    monitor-exit p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    throw v0
.end method

.method public final OooO0OO()Llyiahf/vczjk/a27;
    .locals 1

    iget-object v0, p0, Landroidx/work/impl/WorkDatabase_Impl;->OooO0oO:Llyiahf/vczjk/a27;

    if-eqz v0, :cond_0

    iget-object v0, p0, Landroidx/work/impl/WorkDatabase_Impl;->OooO0oO:Llyiahf/vczjk/a27;

    return-object v0

    :cond_0
    monitor-enter p0

    :try_start_0
    iget-object v0, p0, Landroidx/work/impl/WorkDatabase_Impl;->OooO0oO:Llyiahf/vczjk/a27;

    if-nez v0, :cond_1

    new-instance v0, Llyiahf/vczjk/a27;

    invoke-direct {v0, p0}, Llyiahf/vczjk/a27;-><init>(Landroidx/work/impl/WorkDatabase_Impl;)V

    iput-object v0, p0, Landroidx/work/impl/WorkDatabase_Impl;->OooO0oO:Llyiahf/vczjk/a27;

    goto :goto_0

    :catchall_0
    move-exception v0

    goto :goto_1

    :cond_1
    :goto_0
    iget-object v0, p0, Landroidx/work/impl/WorkDatabase_Impl;->OooO0oO:Llyiahf/vczjk/a27;

    monitor-exit p0

    return-object v0

    :goto_1
    monitor-exit p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    throw v0
.end method

.method public final OooO0Oo()Llyiahf/vczjk/tg7;
    .locals 2

    iget-object v0, p0, Landroidx/work/impl/WorkDatabase_Impl;->OooO0oo:Llyiahf/vczjk/tg7;

    if-eqz v0, :cond_0

    iget-object v0, p0, Landroidx/work/impl/WorkDatabase_Impl;->OooO0oo:Llyiahf/vczjk/tg7;

    return-object v0

    :cond_0
    monitor-enter p0

    :try_start_0
    iget-object v0, p0, Landroidx/work/impl/WorkDatabase_Impl;->OooO0oo:Llyiahf/vczjk/tg7;

    if-nez v0, :cond_1

    new-instance v0, Llyiahf/vczjk/tg7;

    const/4 v1, 0x0

    invoke-direct {v0, p0, v1}, Llyiahf/vczjk/tg7;-><init>(Ljava/lang/Object;I)V

    iput-object v0, p0, Landroidx/work/impl/WorkDatabase_Impl;->OooO0oo:Llyiahf/vczjk/tg7;

    goto :goto_0

    :catchall_0
    move-exception v0

    goto :goto_1

    :cond_1
    :goto_0
    iget-object v0, p0, Landroidx/work/impl/WorkDatabase_Impl;->OooO0oo:Llyiahf/vczjk/tg7;

    monitor-exit p0

    return-object v0

    :goto_1
    monitor-exit p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    throw v0
.end method

.method public final OooO0o()Llyiahf/vczjk/tqa;
    .locals 1

    iget-object v0, p0, Landroidx/work/impl/WorkDatabase_Impl;->OooO0o0:Llyiahf/vczjk/tqa;

    if-eqz v0, :cond_0

    iget-object v0, p0, Landroidx/work/impl/WorkDatabase_Impl;->OooO0o0:Llyiahf/vczjk/tqa;

    return-object v0

    :cond_0
    monitor-enter p0

    :try_start_0
    iget-object v0, p0, Landroidx/work/impl/WorkDatabase_Impl;->OooO0o0:Llyiahf/vczjk/tqa;

    if-nez v0, :cond_1

    new-instance v0, Llyiahf/vczjk/tqa;

    invoke-direct {v0, p0}, Llyiahf/vczjk/tqa;-><init>(Landroidx/work/impl/WorkDatabase_Impl;)V

    iput-object v0, p0, Landroidx/work/impl/WorkDatabase_Impl;->OooO0o0:Llyiahf/vczjk/tqa;

    goto :goto_0

    :catchall_0
    move-exception v0

    goto :goto_1

    :cond_1
    :goto_0
    iget-object v0, p0, Landroidx/work/impl/WorkDatabase_Impl;->OooO0o0:Llyiahf/vczjk/tqa;

    monitor-exit p0

    return-object v0

    :goto_1
    monitor-exit p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    throw v0
.end method

.method public final OooO0o0()Llyiahf/vczjk/ld9;
    .locals 1

    iget-object v0, p0, Landroidx/work/impl/WorkDatabase_Impl;->OooO0Oo:Llyiahf/vczjk/ld9;

    if-eqz v0, :cond_0

    iget-object v0, p0, Landroidx/work/impl/WorkDatabase_Impl;->OooO0Oo:Llyiahf/vczjk/ld9;

    return-object v0

    :cond_0
    monitor-enter p0

    :try_start_0
    iget-object v0, p0, Landroidx/work/impl/WorkDatabase_Impl;->OooO0Oo:Llyiahf/vczjk/ld9;

    if-nez v0, :cond_1

    new-instance v0, Llyiahf/vczjk/ld9;

    invoke-direct {v0, p0}, Llyiahf/vczjk/ld9;-><init>(Landroidx/work/impl/WorkDatabase_Impl;)V

    iput-object v0, p0, Landroidx/work/impl/WorkDatabase_Impl;->OooO0Oo:Llyiahf/vczjk/ld9;

    goto :goto_0

    :catchall_0
    move-exception v0

    goto :goto_1

    :cond_1
    :goto_0
    iget-object v0, p0, Landroidx/work/impl/WorkDatabase_Impl;->OooO0Oo:Llyiahf/vczjk/ld9;

    monitor-exit p0

    return-object v0

    :goto_1
    monitor-exit p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    throw v0
.end method

.method public final OooO0oO()Llyiahf/vczjk/uqa;
    .locals 1

    iget-object v0, p0, Landroidx/work/impl/WorkDatabase_Impl;->OooO0o:Llyiahf/vczjk/uqa;

    if-eqz v0, :cond_0

    iget-object v0, p0, Landroidx/work/impl/WorkDatabase_Impl;->OooO0o:Llyiahf/vczjk/uqa;

    return-object v0

    :cond_0
    monitor-enter p0

    :try_start_0
    iget-object v0, p0, Landroidx/work/impl/WorkDatabase_Impl;->OooO0o:Llyiahf/vczjk/uqa;

    if-nez v0, :cond_1

    new-instance v0, Llyiahf/vczjk/uqa;

    invoke-direct {v0, p0}, Llyiahf/vczjk/uqa;-><init>(Landroidx/work/impl/WorkDatabase_Impl;)V

    iput-object v0, p0, Landroidx/work/impl/WorkDatabase_Impl;->OooO0o:Llyiahf/vczjk/uqa;

    goto :goto_0

    :catchall_0
    move-exception v0

    goto :goto_1

    :cond_1
    :goto_0
    iget-object v0, p0, Landroidx/work/impl/WorkDatabase_Impl;->OooO0o:Llyiahf/vczjk/uqa;

    monitor-exit p0

    return-object v0

    :goto_1
    monitor-exit p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    throw v0
.end method

.method public final OooO0oo()Llyiahf/vczjk/bra;
    .locals 1

    iget-object v0, p0, Landroidx/work/impl/WorkDatabase_Impl;->OooO00o:Llyiahf/vczjk/bra;

    if-eqz v0, :cond_0

    iget-object v0, p0, Landroidx/work/impl/WorkDatabase_Impl;->OooO00o:Llyiahf/vczjk/bra;

    return-object v0

    :cond_0
    monitor-enter p0

    :try_start_0
    iget-object v0, p0, Landroidx/work/impl/WorkDatabase_Impl;->OooO00o:Llyiahf/vczjk/bra;

    if-nez v0, :cond_1

    new-instance v0, Llyiahf/vczjk/bra;

    invoke-direct {v0, p0}, Llyiahf/vczjk/bra;-><init>(Landroidx/work/impl/WorkDatabase_Impl;)V

    iput-object v0, p0, Landroidx/work/impl/WorkDatabase_Impl;->OooO00o:Llyiahf/vczjk/bra;

    goto :goto_0

    :catchall_0
    move-exception v0

    goto :goto_1

    :cond_1
    :goto_0
    iget-object v0, p0, Landroidx/work/impl/WorkDatabase_Impl;->OooO00o:Llyiahf/vczjk/bra;

    monitor-exit p0

    return-object v0

    :goto_1
    monitor-exit p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    throw v0
.end method

.method public final clearAllTables()V
    .locals 4

    const-string v0, "VACUUM"

    const-string v1, "PRAGMA wal_checkpoint(FULL)"

    invoke-super {p0}, Llyiahf/vczjk/ru7;->assertNotMainThread()V

    invoke-super {p0}, Llyiahf/vczjk/ru7;->getOpenHelper()Llyiahf/vczjk/ea9;

    move-result-object v2

    invoke-interface {v2}, Llyiahf/vczjk/ea9;->OoooOOO()Llyiahf/vczjk/ca9;

    move-result-object v2

    :try_start_0
    invoke-super {p0}, Llyiahf/vczjk/ru7;->beginTransaction()V

    const-string v3, "PRAGMA defer_foreign_keys = TRUE"

    invoke-interface {v2, v3}, Llyiahf/vczjk/ca9;->OooOO0o(Ljava/lang/String;)V

    const-string v3, "DELETE FROM `Dependency`"

    invoke-interface {v2, v3}, Llyiahf/vczjk/ca9;->OooOO0o(Ljava/lang/String;)V

    const-string v3, "DELETE FROM `WorkSpec`"

    invoke-interface {v2, v3}, Llyiahf/vczjk/ca9;->OooOO0o(Ljava/lang/String;)V

    const-string v3, "DELETE FROM `WorkTag`"

    invoke-interface {v2, v3}, Llyiahf/vczjk/ca9;->OooOO0o(Ljava/lang/String;)V

    const-string v3, "DELETE FROM `SystemIdInfo`"

    invoke-interface {v2, v3}, Llyiahf/vczjk/ca9;->OooOO0o(Ljava/lang/String;)V

    const-string v3, "DELETE FROM `WorkName`"

    invoke-interface {v2, v3}, Llyiahf/vczjk/ca9;->OooOO0o(Ljava/lang/String;)V

    const-string v3, "DELETE FROM `WorkProgress`"

    invoke-interface {v2, v3}, Llyiahf/vczjk/ca9;->OooOO0o(Ljava/lang/String;)V

    const-string v3, "DELETE FROM `Preference`"

    invoke-interface {v2, v3}, Llyiahf/vczjk/ca9;->OooOO0o(Ljava/lang/String;)V

    invoke-super {p0}, Llyiahf/vczjk/ru7;->setTransactionSuccessful()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    invoke-super {p0}, Llyiahf/vczjk/ru7;->endTransaction()V

    invoke-interface {v2, v1}, Llyiahf/vczjk/ca9;->OoooOo0(Ljava/lang/String;)Landroid/database/Cursor;

    move-result-object v1

    invoke-interface {v1}, Landroid/database/Cursor;->close()V

    invoke-interface {v2}, Llyiahf/vczjk/ca9;->o00ooo()Z

    move-result v1

    if-nez v1, :cond_0

    invoke-interface {v2, v0}, Llyiahf/vczjk/ca9;->OooOO0o(Ljava/lang/String;)V

    :cond_0
    return-void

    :catchall_0
    move-exception v3

    invoke-super {p0}, Llyiahf/vczjk/ru7;->endTransaction()V

    invoke-interface {v2, v1}, Llyiahf/vczjk/ca9;->OoooOo0(Ljava/lang/String;)Landroid/database/Cursor;

    move-result-object v1

    invoke-interface {v1}, Landroid/database/Cursor;->close()V

    invoke-interface {v2}, Llyiahf/vczjk/ca9;->o00ooo()Z

    move-result v1

    if-nez v1, :cond_1

    invoke-interface {v2, v0}, Llyiahf/vczjk/ca9;->OooOO0o(Ljava/lang/String;)V

    :cond_1
    throw v3
.end method

.method public final createInvalidationTracker()Llyiahf/vczjk/q44;
    .locals 10

    new-instance v0, Ljava/util/HashMap;

    const/4 v1, 0x0

    invoke-direct {v0, v1}, Ljava/util/HashMap;-><init>(I)V

    new-instance v2, Ljava/util/HashMap;

    invoke-direct {v2, v1}, Ljava/util/HashMap;-><init>(I)V

    new-instance v1, Llyiahf/vczjk/q44;

    const-string v6, "SystemIdInfo"

    const-string v7, "WorkName"

    const-string v3, "Dependency"

    const-string v4, "WorkSpec"

    const-string v5, "WorkTag"

    const-string v8, "WorkProgress"

    const-string v9, "Preference"

    filled-new-array/range {v3 .. v9}, [Ljava/lang/String;

    move-result-object v3

    invoke-direct {v1, p0, v0, v2, v3}, Llyiahf/vczjk/q44;-><init>(Llyiahf/vczjk/ru7;Ljava/util/HashMap;Ljava/util/HashMap;[Ljava/lang/String;)V

    return-object v1
.end method

.method public final createOpenHelper(Llyiahf/vczjk/oz1;)Llyiahf/vczjk/ea9;
    .locals 6

    new-instance v3, Llyiahf/vczjk/wu7;

    new-instance v0, Llyiahf/vczjk/tw7;

    invoke-direct {v0, p0}, Llyiahf/vczjk/tw7;-><init>(Landroidx/work/impl/WorkDatabase_Impl;)V

    const-string v1, "86254750241babac4b8d52996a675549"

    const-string v2, "1cbd3130fa23b59692c061c594c16cc0"

    invoke-direct {v3, p1, v0, v1, v2}, Llyiahf/vczjk/wu7;-><init>(Llyiahf/vczjk/oz1;Llyiahf/vczjk/vu7;Ljava/lang/String;Ljava/lang/String;)V

    iget-object v1, p1, Llyiahf/vczjk/oz1;->OooO00o:Landroid/content/Context;

    const-string v0, "context"

    invoke-static {v1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v0, Llyiahf/vczjk/bv0;

    const/4 v5, 0x0

    const/4 v4, 0x0

    iget-object v2, p1, Llyiahf/vczjk/oz1;->OooO0O0:Ljava/lang/String;

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/bv0;-><init>(Landroid/content/Context;Ljava/lang/String;Llyiahf/vczjk/vu7;ZZ)V

    iget-object p1, p1, Llyiahf/vczjk/oz1;->OooO0OO:Llyiahf/vczjk/da9;

    invoke-interface {p1, v0}, Llyiahf/vczjk/da9;->OooO0OO(Llyiahf/vczjk/bv0;)Llyiahf/vczjk/ea9;

    move-result-object p1

    return-object p1
.end method

.method public final getAutoMigrations(Ljava/util/Map;)Ljava/util/List;
    .locals 4

    new-instance p1, Ljava/util/ArrayList;

    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    new-instance v0, Llyiahf/vczjk/fj5;

    const/16 v1, 0xd

    const/16 v2, 0xe

    const/16 v3, 0xa

    invoke-direct {v0, v1, v2, v3}, Llyiahf/vczjk/fj5;-><init>(III)V

    invoke-virtual {p1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    new-instance v0, Llyiahf/vczjk/fj5;

    const/16 v1, 0xb

    invoke-direct {v0, v1}, Llyiahf/vczjk/fj5;-><init>(I)V

    invoke-virtual {p1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    new-instance v0, Llyiahf/vczjk/fj5;

    const/16 v1, 0x10

    const/16 v2, 0x11

    const/16 v3, 0xc

    invoke-direct {v0, v1, v2, v3}, Llyiahf/vczjk/fj5;-><init>(III)V

    invoke-virtual {p1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    new-instance v0, Llyiahf/vczjk/fj5;

    const/16 v1, 0x12

    const/16 v3, 0xd

    invoke-direct {v0, v2, v1, v3}, Llyiahf/vczjk/fj5;-><init>(III)V

    invoke-virtual {p1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    new-instance v0, Llyiahf/vczjk/fj5;

    const/16 v2, 0x13

    const/16 v3, 0xe

    invoke-direct {v0, v1, v2, v3}, Llyiahf/vczjk/fj5;-><init>(III)V

    invoke-virtual {p1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    new-instance v0, Llyiahf/vczjk/fj5;

    const/16 v1, 0xf

    invoke-direct {v0, v1}, Llyiahf/vczjk/fj5;-><init>(I)V

    invoke-virtual {p1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    new-instance v0, Llyiahf/vczjk/fj5;

    const/16 v1, 0x14

    const/16 v2, 0x15

    const/16 v3, 0x10

    invoke-direct {v0, v1, v2, v3}, Llyiahf/vczjk/fj5;-><init>(III)V

    invoke-virtual {p1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    new-instance v0, Llyiahf/vczjk/fj5;

    const/16 v1, 0x16

    const/16 v2, 0x17

    const/16 v3, 0x11

    invoke-direct {v0, v1, v2, v3}, Llyiahf/vczjk/fj5;-><init>(III)V

    invoke-virtual {p1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    return-object p1
.end method

.method public final getRequiredAutoMigrationSpecs()Ljava/util/Set;
    .locals 1

    new-instance v0, Ljava/util/HashSet;

    invoke-direct {v0}, Ljava/util/HashSet;-><init>()V

    return-object v0
.end method

.method public final getRequiredTypeConverters()Ljava/util/Map;
    .locals 3

    new-instance v0, Ljava/util/HashMap;

    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    sget-object v1, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    const-class v2, Llyiahf/vczjk/bra;

    invoke-virtual {v0, v2, v1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    const-class v2, Llyiahf/vczjk/n62;

    invoke-virtual {v0, v2, v1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    const-class v2, Llyiahf/vczjk/era;

    invoke-virtual {v0, v2, v1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    const-class v2, Llyiahf/vczjk/ld9;

    invoke-virtual {v0, v2, v1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    const-class v2, Llyiahf/vczjk/tqa;

    invoke-virtual {v0, v2, v1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    const-class v2, Llyiahf/vczjk/uqa;

    invoke-virtual {v0, v2, v1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    const-class v2, Llyiahf/vczjk/a27;

    invoke-virtual {v0, v2, v1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    const-class v2, Llyiahf/vczjk/tg7;

    invoke-virtual {v0, v2, v1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    return-object v0
.end method

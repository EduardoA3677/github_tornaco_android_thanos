.class public abstract Llyiahf/vczjk/o17;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final synthetic OooO00o:[Llyiahf/vczjk/th4;

.field public static final OooO0O0:Llyiahf/vczjk/f27;

.field public static final OooO0OO:Llyiahf/vczjk/v27;

.field public static final OooO0Oo:Llyiahf/vczjk/v27;


# direct methods
.method static constructor <clinit>()V
    .locals 5

    new-instance v0, Llyiahf/vczjk/za7;

    const-string v1, "getDataStore(Landroid/content/Context;)Landroidx/datastore/core/DataStore;"

    const/4 v2, 0x1

    const-class v3, Llyiahf/vczjk/o17;

    const-string v4, "dataStore"

    invoke-direct {v0, v3, v4, v1, v2}, Llyiahf/vczjk/za7;-><init>(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;I)V

    sget-object v1, Llyiahf/vczjk/ym7;->OooO00o:Llyiahf/vczjk/zm7;

    invoke-virtual {v1, v0}, Llyiahf/vczjk/zm7;->OooO0oO(Llyiahf/vczjk/za7;)Llyiahf/vczjk/mh4;

    move-result-object v0

    new-array v1, v2, [Llyiahf/vczjk/th4;

    const/4 v2, 0x0

    aput-object v0, v1, v2

    sput-object v1, Llyiahf/vczjk/o17;->OooO00o:[Llyiahf/vczjk/th4;

    sget-object v0, Llyiahf/vczjk/k65;->Oooo0OO:Llyiahf/vczjk/k65;

    sget-object v1, Llyiahf/vczjk/kc2;->OooO00o:Llyiahf/vczjk/q32;

    sget-object v1, Llyiahf/vczjk/m22;->OooOOOO:Llyiahf/vczjk/m22;

    invoke-static {}, Llyiahf/vczjk/vl6;->OooO0O0()Llyiahf/vczjk/u99;

    move-result-object v2

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v1, v2}, Llyiahf/vczjk/tg0;->Oooo000(Llyiahf/vczjk/mr1;Llyiahf/vczjk/or1;)Llyiahf/vczjk/or1;

    move-result-object v1

    invoke-static {v1}, Llyiahf/vczjk/v34;->OooO0oO(Llyiahf/vczjk/or1;)Llyiahf/vczjk/to1;

    move-result-object v1

    new-instance v2, Llyiahf/vczjk/f27;

    invoke-direct {v2, v0, v1}, Llyiahf/vczjk/f27;-><init>(Llyiahf/vczjk/oe3;Llyiahf/vczjk/xr1;)V

    sput-object v2, Llyiahf/vczjk/o17;->OooO0O0:Llyiahf/vczjk/f27;

    new-instance v0, Llyiahf/vczjk/v27;

    const-string v1, "UI_THEME_DARK_MODE_CONFIG"

    invoke-direct {v0, v1}, Llyiahf/vczjk/v27;-><init>(Ljava/lang/String;)V

    sput-object v0, Llyiahf/vczjk/o17;->OooO0OO:Llyiahf/vczjk/v27;

    new-instance v0, Llyiahf/vczjk/v27;

    const-string v1, "UI_THEME_DYNAMIC_COLOR"

    invoke-direct {v0, v1}, Llyiahf/vczjk/v27;-><init>(Ljava/lang/String;)V

    sput-object v0, Llyiahf/vczjk/o17;->OooO0Oo:Llyiahf/vczjk/v27;

    return-void
.end method

.method public static final OooO00o(Landroid/content/Context;)Llyiahf/vczjk/ay1;
    .locals 8

    const-string v0, "<this>"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v0, Llyiahf/vczjk/o17;->OooO0O0:Llyiahf/vczjk/f27;

    sget-object v1, Llyiahf/vczjk/o17;->OooO00o:[Llyiahf/vczjk/th4;

    const/4 v2, 0x0

    aget-object v1, v1, v2

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const-string v2, "property"

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v1, v0, Llyiahf/vczjk/f27;->OooO0Oo:Llyiahf/vczjk/c27;

    if-nez v1, :cond_1

    iget-object v1, v0, Llyiahf/vczjk/f27;->OooO0OO:Ljava/lang/Object;

    monitor-enter v1

    :try_start_0
    iget-object v2, v0, Llyiahf/vczjk/f27;->OooO0Oo:Llyiahf/vczjk/c27;

    if-nez v2, :cond_0

    invoke-virtual {p0}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    move-result-object p0

    iget-object v2, v0, Llyiahf/vczjk/f27;->OooO00o:Llyiahf/vczjk/oe3;

    const-string v3, "applicationContext"

    invoke-static {p0, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {v2, p0}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/util/List;

    iget-object v3, v0, Llyiahf/vczjk/f27;->OooO0O0:Llyiahf/vczjk/xr1;

    new-instance v4, Llyiahf/vczjk/e27;

    invoke-direct {v4, p0, v0}, Llyiahf/vczjk/e27;-><init>(Landroid/content/Context;Llyiahf/vczjk/f27;)V

    const-string p0, "migrations"

    invoke-static {v2, p0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance p0, Llyiahf/vczjk/m96;

    sget-object v5, Llyiahf/vczjk/ez2;->OooO00o:Llyiahf/vczjk/we4;

    sget-object v6, Llyiahf/vczjk/e86;->OooOOo:Llyiahf/vczjk/e86;

    new-instance v7, Llyiahf/vczjk/d27;

    invoke-direct {v7, v4}, Llyiahf/vczjk/d27;-><init>(Llyiahf/vczjk/e27;)V

    invoke-direct {p0, v5, v6, v7}, Llyiahf/vczjk/m96;-><init>(Llyiahf/vczjk/we4;Llyiahf/vczjk/j96;Llyiahf/vczjk/le3;)V

    new-instance v4, Llyiahf/vczjk/c27;

    new-instance v5, Llyiahf/vczjk/pp3;

    const/16 v6, 0x14

    invoke-direct {v5, v6}, Llyiahf/vczjk/pp3;-><init>(I)V

    new-instance v6, Llyiahf/vczjk/rx1;

    const/4 v7, 0x0

    invoke-direct {v6, v2, v7}, Llyiahf/vczjk/rx1;-><init>(Ljava/util/List;Llyiahf/vczjk/yo1;)V

    invoke-static {v6}, Llyiahf/vczjk/r02;->OooOo(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v2

    new-instance v6, Llyiahf/vczjk/jz1;

    invoke-direct {v6, p0, v2, v5, v3}, Llyiahf/vczjk/jz1;-><init>(Llyiahf/vczjk/m96;Ljava/util/List;Llyiahf/vczjk/pp3;Llyiahf/vczjk/xr1;)V

    invoke-direct {v4, v6}, Llyiahf/vczjk/c27;-><init>(Llyiahf/vczjk/ay1;)V

    new-instance p0, Llyiahf/vczjk/c27;

    invoke-direct {p0, v4}, Llyiahf/vczjk/c27;-><init>(Llyiahf/vczjk/ay1;)V

    iput-object p0, v0, Llyiahf/vczjk/f27;->OooO0Oo:Llyiahf/vczjk/c27;

    goto :goto_0

    :catchall_0
    move-exception p0

    goto :goto_1

    :cond_0
    :goto_0
    iget-object p0, v0, Llyiahf/vczjk/f27;->OooO0Oo:Llyiahf/vczjk/c27;

    invoke-static {p0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    monitor-exit v1

    return-object p0

    :goto_1
    monitor-exit v1

    throw p0

    :cond_1
    return-object v1
.end method

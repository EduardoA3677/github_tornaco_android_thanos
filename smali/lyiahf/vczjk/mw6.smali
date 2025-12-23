.class public abstract Llyiahf/vczjk/mw6;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final synthetic OooO00o:[Llyiahf/vczjk/th4;

.field public static final OooO0O0:Llyiahf/vczjk/lz1;


# direct methods
.method static constructor <clinit>()V
    .locals 5

    new-instance v0, Llyiahf/vczjk/za7;

    const-class v1, Llyiahf/vczjk/mw6;

    const-string v2, "sfPkgSetDataStore"

    const-string v3, "getSfPkgSetDataStore(Landroid/content/Context;)Landroidx/datastore/core/DataStore;"

    const/4 v4, 0x1

    invoke-direct {v0, v1, v2, v3, v4}, Llyiahf/vczjk/za7;-><init>(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;I)V

    sget-object v1, Llyiahf/vczjk/ym7;->OooO00o:Llyiahf/vczjk/zm7;

    invoke-virtual {v1, v0}, Llyiahf/vczjk/zm7;->OooO0oO(Llyiahf/vczjk/za7;)Llyiahf/vczjk/mh4;

    move-result-object v0

    new-array v1, v4, [Llyiahf/vczjk/th4;

    const/4 v2, 0x0

    aput-object v0, v1, v2

    sput-object v1, Llyiahf/vczjk/mw6;->OooO00o:[Llyiahf/vczjk/th4;

    sget-object v0, Llyiahf/vczjk/lw6;->OooO00o:Llyiahf/vczjk/lw6;

    const-string v1, "sf_pkg_set.pb"

    invoke-static {v1, v0}, Llyiahf/vczjk/qqa;->OooOoOO(Ljava/lang/String;Llyiahf/vczjk/og8;)Llyiahf/vczjk/lz1;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/mw6;->OooO0O0:Llyiahf/vczjk/lz1;

    return-void
.end method

.method public static final OooO00o(Landroid/content/Context;)Llyiahf/vczjk/ay1;
    .locals 2

    const-string v0, "<this>"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v0, Llyiahf/vczjk/mw6;->OooO00o:[Llyiahf/vczjk/th4;

    const/4 v1, 0x0

    aget-object v0, v0, v1

    sget-object v1, Llyiahf/vczjk/mw6;->OooO0O0:Llyiahf/vczjk/lz1;

    invoke-virtual {v1, p0, v0}, Llyiahf/vczjk/lz1;->OooO00o(Ljava/lang/Object;Llyiahf/vczjk/th4;)Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Llyiahf/vczjk/ay1;

    return-object p0
.end method

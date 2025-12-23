.class public final Llyiahf/vczjk/ow4;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic $currentRegistry:Llyiahf/vczjk/t58;

.field final synthetic $wrappedHolder:Llyiahf/vczjk/o58;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/t58;Llyiahf/vczjk/r58;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ow4;->$currentRegistry:Llyiahf/vczjk/t58;

    iput-object p2, p0, Llyiahf/vczjk/ow4;->$wrappedHolder:Llyiahf/vczjk/o58;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 4

    new-instance v0, Llyiahf/vczjk/lw4;

    iget-object v1, p0, Llyiahf/vczjk/ow4;->$currentRegistry:Llyiahf/vczjk/t58;

    sget-object v2, Llyiahf/vczjk/bn2;->OooOOO0:Llyiahf/vczjk/bn2;

    iget-object v3, p0, Llyiahf/vczjk/ow4;->$wrappedHolder:Llyiahf/vczjk/o58;

    invoke-direct {v0, v1, v2, v3}, Llyiahf/vczjk/lw4;-><init>(Llyiahf/vczjk/t58;Ljava/util/Map;Llyiahf/vczjk/o58;)V

    return-object v0
.end method

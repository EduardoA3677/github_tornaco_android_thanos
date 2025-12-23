.class public final Llyiahf/vczjk/aj;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $placeable:Llyiahf/vczjk/ow6;

.field final synthetic $specOnEnter:Llyiahf/vczjk/fn1;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ow6;Llyiahf/vczjk/fn1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/aj;->$placeable:Llyiahf/vczjk/ow6;

    iput-object p2, p0, Llyiahf/vczjk/aj;->$specOnEnter:Llyiahf/vczjk/fn1;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    check-cast p1, Llyiahf/vczjk/nw6;

    iget-object v0, p0, Llyiahf/vczjk/aj;->$placeable:Llyiahf/vczjk/ow6;

    iget-object v1, p0, Llyiahf/vczjk/aj;->$specOnEnter:Llyiahf/vczjk/fn1;

    iget-object v1, v1, Llyiahf/vczjk/fn1;->OooO0OO:Llyiahf/vczjk/lr5;

    check-cast v1, Llyiahf/vczjk/zv8;

    invoke-virtual {v1}, Llyiahf/vczjk/zv8;->OooOOoo()F

    move-result v1

    const/4 v2, 0x0

    invoke-virtual {p1, v0, v2, v2, v1}, Llyiahf/vczjk/nw6;->OooO0o0(Llyiahf/vczjk/ow6;IIF)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method

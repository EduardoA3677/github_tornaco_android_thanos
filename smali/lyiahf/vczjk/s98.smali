.class public final Llyiahf/vczjk/s98;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $placeable:Llyiahf/vczjk/ow6;

.field final synthetic $side:I

.field final synthetic this$0:Llyiahf/vczjk/t98;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/t98;ILlyiahf/vczjk/ow6;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/s98;->this$0:Llyiahf/vczjk/t98;

    iput p2, p0, Llyiahf/vczjk/s98;->$side:I

    iput-object p3, p0, Llyiahf/vczjk/s98;->$placeable:Llyiahf/vczjk/ow6;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    check-cast p1, Llyiahf/vczjk/nw6;

    iget-object v0, p0, Llyiahf/vczjk/s98;->this$0:Llyiahf/vczjk/t98;

    iget-object v0, v0, Llyiahf/vczjk/t98;->OooOoOO:Llyiahf/vczjk/z98;

    invoke-virtual {v0}, Llyiahf/vczjk/z98;->OooO0o()I

    move-result v0

    iget v1, p0, Llyiahf/vczjk/s98;->$side:I

    const/4 v2, 0x0

    if-gez v0, :cond_0

    move v0, v2

    :cond_0
    if-le v0, v1, :cond_1

    goto :goto_0

    :cond_1
    move v1, v0

    :goto_0
    iget-object v0, p0, Llyiahf/vczjk/s98;->this$0:Llyiahf/vczjk/t98;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    neg-int v1, v1

    iget-boolean v0, v0, Llyiahf/vczjk/t98;->OooOoo0:Z

    if-eqz v0, :cond_2

    move v3, v2

    goto :goto_1

    :cond_2
    move v3, v1

    :goto_1
    if-eqz v0, :cond_3

    goto :goto_2

    :cond_3
    move v1, v2

    :goto_2
    new-instance v0, Llyiahf/vczjk/r98;

    iget-object v4, p0, Llyiahf/vczjk/s98;->$placeable:Llyiahf/vczjk/ow6;

    invoke-direct {v0, v4, v3, v1}, Llyiahf/vczjk/r98;-><init>(Llyiahf/vczjk/ow6;II)V

    const/4 v1, 0x1

    iput-boolean v1, p1, Llyiahf/vczjk/nw6;->OooO00o:Z

    invoke-virtual {v0, p1}, Llyiahf/vczjk/r98;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    iput-boolean v2, p1, Llyiahf/vczjk/nw6;->OooO00o:Z

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method

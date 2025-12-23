.class public final Llyiahf/vczjk/efa;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $height:I

.field final synthetic $placeable:Llyiahf/vczjk/ow6;

.field final synthetic $this_measure:Llyiahf/vczjk/nf5;

.field final synthetic this$0:Llyiahf/vczjk/ffa;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/nf5;Llyiahf/vczjk/ffa;Llyiahf/vczjk/ow6;I)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/efa;->$this_measure:Llyiahf/vczjk/nf5;

    iput-object p2, p0, Llyiahf/vczjk/efa;->this$0:Llyiahf/vczjk/ffa;

    iput-object p3, p0, Llyiahf/vczjk/efa;->$placeable:Llyiahf/vczjk/ow6;

    iput p4, p0, Llyiahf/vczjk/efa;->$height:I

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    check-cast p1, Llyiahf/vczjk/nw6;

    iget-object v0, p0, Llyiahf/vczjk/efa;->$this_measure:Llyiahf/vczjk/nf5;

    iget-object v1, p0, Llyiahf/vczjk/efa;->this$0:Llyiahf/vczjk/ffa;

    move-object v2, v1

    iget v1, v2, Llyiahf/vczjk/ffa;->OooOOO:I

    iget-object v3, v2, Llyiahf/vczjk/ffa;->OooOOOo:Llyiahf/vczjk/le3;

    invoke-interface {v3}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/nm9;

    if-eqz v3, :cond_0

    iget-object v3, v3, Llyiahf/vczjk/nm9;->OooO00o:Llyiahf/vczjk/mm9;

    goto :goto_0

    :cond_0
    const/4 v3, 0x0

    :goto_0
    iget-object v4, p0, Llyiahf/vczjk/efa;->$placeable:Llyiahf/vczjk/ow6;

    iget v5, v4, Llyiahf/vczjk/ow6;->OooOOO0:I

    iget-object v2, v2, Llyiahf/vczjk/ffa;->OooOOOO:Llyiahf/vczjk/gy9;

    const/4 v4, 0x0

    invoke-static/range {v0 .. v5}, Llyiahf/vczjk/kh6;->OooO0oo(Llyiahf/vczjk/f62;ILlyiahf/vczjk/gy9;Llyiahf/vczjk/mm9;ZI)Llyiahf/vczjk/wj7;

    move-result-object v0

    iget-object v1, p0, Llyiahf/vczjk/efa;->this$0:Llyiahf/vczjk/ffa;

    iget-object v1, v1, Llyiahf/vczjk/ffa;->OooOOO0:Llyiahf/vczjk/vj9;

    sget-object v2, Llyiahf/vczjk/nf6;->OooOOO0:Llyiahf/vczjk/nf6;

    iget v3, p0, Llyiahf/vczjk/efa;->$height:I

    iget-object v4, p0, Llyiahf/vczjk/efa;->$placeable:Llyiahf/vczjk/ow6;

    iget v4, v4, Llyiahf/vczjk/ow6;->OooOOO:I

    invoke-virtual {v1, v2, v0, v3, v4}, Llyiahf/vczjk/vj9;->OooO0O0(Llyiahf/vczjk/nf6;Llyiahf/vczjk/wj7;II)V

    iget-object v0, p0, Llyiahf/vczjk/efa;->this$0:Llyiahf/vczjk/ffa;

    iget-object v0, v0, Llyiahf/vczjk/ffa;->OooOOO0:Llyiahf/vczjk/vj9;

    invoke-virtual {v0}, Llyiahf/vczjk/vj9;->OooO00o()F

    move-result v0

    neg-float v0, v0

    iget-object v1, p0, Llyiahf/vczjk/efa;->$placeable:Llyiahf/vczjk/ow6;

    invoke-static {v0}, Ljava/lang/Math;->round(F)I

    move-result v0

    const/4 v2, 0x0

    invoke-static {p1, v1, v2, v0}, Llyiahf/vczjk/nw6;->OooO0oo(Llyiahf/vczjk/nw6;Llyiahf/vczjk/ow6;II)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method

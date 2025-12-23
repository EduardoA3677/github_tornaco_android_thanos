.class public final Llyiahf/vczjk/t86;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $placeable:Llyiahf/vczjk/ow6;

.field final synthetic $this_measure:Llyiahf/vczjk/nf5;

.field final synthetic this$0:Llyiahf/vczjk/u86;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/u86;Llyiahf/vczjk/ow6;Llyiahf/vczjk/nf5;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/t86;->this$0:Llyiahf/vczjk/u86;

    iput-object p2, p0, Llyiahf/vczjk/t86;->$placeable:Llyiahf/vczjk/ow6;

    iput-object p3, p0, Llyiahf/vczjk/t86;->$this_measure:Llyiahf/vczjk/nf5;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    check-cast p1, Llyiahf/vczjk/nw6;

    iget-object v0, p0, Llyiahf/vczjk/t86;->this$0:Llyiahf/vczjk/u86;

    iget-boolean v1, v0, Llyiahf/vczjk/u86;->OooOoo:Z

    if-eqz v1, :cond_0

    iget-object v1, p0, Llyiahf/vczjk/t86;->$placeable:Llyiahf/vczjk/ow6;

    iget-object v2, p0, Llyiahf/vczjk/t86;->$this_measure:Llyiahf/vczjk/nf5;

    iget v0, v0, Llyiahf/vczjk/u86;->OooOoOO:F

    invoke-interface {v2, v0}, Llyiahf/vczjk/f62;->o00Oo0(F)I

    move-result v0

    iget-object v2, p0, Llyiahf/vczjk/t86;->$this_measure:Llyiahf/vczjk/nf5;

    iget-object v3, p0, Llyiahf/vczjk/t86;->this$0:Llyiahf/vczjk/u86;

    iget v3, v3, Llyiahf/vczjk/u86;->OooOoo0:F

    invoke-interface {v2, v3}, Llyiahf/vczjk/f62;->o00Oo0(F)I

    move-result v2

    invoke-static {p1, v1, v0, v2}, Llyiahf/vczjk/nw6;->OooO0oo(Llyiahf/vczjk/nw6;Llyiahf/vczjk/ow6;II)V

    goto :goto_0

    :cond_0
    iget-object v1, p0, Llyiahf/vczjk/t86;->$placeable:Llyiahf/vczjk/ow6;

    iget-object v2, p0, Llyiahf/vczjk/t86;->$this_measure:Llyiahf/vczjk/nf5;

    iget v0, v0, Llyiahf/vczjk/u86;->OooOoOO:F

    invoke-interface {v2, v0}, Llyiahf/vczjk/f62;->o00Oo0(F)I

    move-result v0

    iget-object v2, p0, Llyiahf/vczjk/t86;->$this_measure:Llyiahf/vczjk/nf5;

    iget-object v3, p0, Llyiahf/vczjk/t86;->this$0:Llyiahf/vczjk/u86;

    iget v3, v3, Llyiahf/vczjk/u86;->OooOoo0:F

    invoke-interface {v2, v3}, Llyiahf/vczjk/f62;->o00Oo0(F)I

    move-result v2

    invoke-static {p1, v1, v0, v2}, Llyiahf/vczjk/nw6;->OooO0o(Llyiahf/vczjk/nw6;Llyiahf/vczjk/ow6;II)V

    :goto_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method

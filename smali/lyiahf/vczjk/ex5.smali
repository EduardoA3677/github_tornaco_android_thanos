.class public final synthetic Llyiahf/vczjk/ex5;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/ow6;

.field public final synthetic OooOOO0:Llyiahf/vczjk/ow6;

.field public final synthetic OooOOOO:I

.field public final synthetic OooOOOo:F

.field public final synthetic OooOOo:Llyiahf/vczjk/ow6;

.field public final synthetic OooOOo0:F

.field public final synthetic OooOOoo:I

.field public final synthetic OooOo:I

.field public final synthetic OooOo0:Llyiahf/vczjk/ow6;

.field public final synthetic OooOo00:F

.field public final synthetic OooOo0O:I

.field public final synthetic OooOo0o:F

.field public final synthetic OooOoO0:Llyiahf/vczjk/nf5;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/ow6;FLlyiahf/vczjk/ow6;IFFLlyiahf/vczjk/ow6;IFLlyiahf/vczjk/ow6;IFILlyiahf/vczjk/nf5;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/ex5;->OooOOO0:Llyiahf/vczjk/ow6;

    iput-object p3, p0, Llyiahf/vczjk/ex5;->OooOOO:Llyiahf/vczjk/ow6;

    iput p4, p0, Llyiahf/vczjk/ex5;->OooOOOO:I

    iput p5, p0, Llyiahf/vczjk/ex5;->OooOOOo:F

    iput p6, p0, Llyiahf/vczjk/ex5;->OooOOo0:F

    iput-object p7, p0, Llyiahf/vczjk/ex5;->OooOOo:Llyiahf/vczjk/ow6;

    iput p8, p0, Llyiahf/vczjk/ex5;->OooOOoo:I

    iput p9, p0, Llyiahf/vczjk/ex5;->OooOo00:F

    iput-object p10, p0, Llyiahf/vczjk/ex5;->OooOo0:Llyiahf/vczjk/ow6;

    iput p11, p0, Llyiahf/vczjk/ex5;->OooOo0O:I

    iput p12, p0, Llyiahf/vczjk/ex5;->OooOo0o:F

    iput p13, p0, Llyiahf/vczjk/ex5;->OooOo:I

    iput-object p14, p0, Llyiahf/vczjk/ex5;->OooOoO0:Llyiahf/vczjk/nf5;

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    check-cast p1, Llyiahf/vczjk/nw6;

    iget-object v0, p0, Llyiahf/vczjk/ex5;->OooOOO0:Llyiahf/vczjk/ow6;

    iget v1, p0, Llyiahf/vczjk/ex5;->OooOOo0:F

    iget v2, p0, Llyiahf/vczjk/ex5;->OooOo00:F

    if-eqz v0, :cond_0

    iget v3, v0, Llyiahf/vczjk/ow6;->OooOOO0:I

    iget v4, p0, Llyiahf/vczjk/ex5;->OooOo:I

    sub-int/2addr v4, v3

    div-int/lit8 v4, v4, 0x2

    sget v3, Llyiahf/vczjk/hx5;->OooO0o0:F

    iget-object v5, p0, Llyiahf/vczjk/ex5;->OooOoO0:Llyiahf/vczjk/nf5;

    invoke-interface {v5, v3}, Llyiahf/vczjk/f62;->o00Oo0(F)I

    move-result v3

    int-to-float v3, v3

    sub-float v3, v2, v3

    add-float/2addr v3, v1

    invoke-static {v3}, Llyiahf/vczjk/ye5;->Oooo000(F)I

    move-result v3

    invoke-static {p1, v0, v4, v3}, Llyiahf/vczjk/nw6;->OooO0oo(Llyiahf/vczjk/nw6;Llyiahf/vczjk/ow6;II)V

    :cond_0
    iget v0, p0, Llyiahf/vczjk/ex5;->OooOOOo:F

    add-float/2addr v0, v1

    invoke-static {v0}, Llyiahf/vczjk/ye5;->Oooo000(F)I

    move-result v0

    iget-object v3, p0, Llyiahf/vczjk/ex5;->OooOOO:Llyiahf/vczjk/ow6;

    iget v4, p0, Llyiahf/vczjk/ex5;->OooOOOO:I

    invoke-static {p1, v3, v4, v0}, Llyiahf/vczjk/nw6;->OooO0oo(Llyiahf/vczjk/nw6;Llyiahf/vczjk/ow6;II)V

    add-float/2addr v2, v1

    invoke-static {v2}, Llyiahf/vczjk/ye5;->Oooo000(F)I

    move-result v0

    iget-object v2, p0, Llyiahf/vczjk/ex5;->OooOOo:Llyiahf/vczjk/ow6;

    iget v3, p0, Llyiahf/vczjk/ex5;->OooOOoo:I

    invoke-static {p1, v2, v3, v0}, Llyiahf/vczjk/nw6;->OooO0oo(Llyiahf/vczjk/nw6;Llyiahf/vczjk/ow6;II)V

    iget v0, p0, Llyiahf/vczjk/ex5;->OooOo0o:F

    add-float/2addr v0, v1

    invoke-static {v0}, Llyiahf/vczjk/ye5;->Oooo000(F)I

    move-result v0

    iget-object v1, p0, Llyiahf/vczjk/ex5;->OooOo0:Llyiahf/vczjk/ow6;

    iget v2, p0, Llyiahf/vczjk/ex5;->OooOo0O:I

    invoke-static {p1, v1, v2, v0}, Llyiahf/vczjk/nw6;->OooO0oo(Llyiahf/vczjk/nw6;Llyiahf/vczjk/ow6;II)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method

.class public final synthetic Llyiahf/vczjk/t68;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/ow6;

.field public final synthetic OooOOO0:Llyiahf/vczjk/ow6;

.field public final synthetic OooOOOO:Llyiahf/vczjk/ow6;

.field public final synthetic OooOOOo:I

.field public final synthetic OooOOo:Llyiahf/vczjk/e89;

.field public final synthetic OooOOo0:Llyiahf/vczjk/kna;

.field public final synthetic OooOOoo:I

.field public final synthetic OooOo:Ljava/lang/Integer;

.field public final synthetic OooOo0:Llyiahf/vczjk/ow6;

.field public final synthetic OooOo00:I

.field public final synthetic OooOo0O:Llyiahf/vczjk/yu2;

.field public final synthetic OooOo0o:Llyiahf/vczjk/ow6;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/ow6;Llyiahf/vczjk/ow6;Llyiahf/vczjk/ow6;ILlyiahf/vczjk/kna;Llyiahf/vczjk/e89;IILlyiahf/vczjk/ow6;Llyiahf/vczjk/yu2;Llyiahf/vczjk/ow6;Ljava/lang/Integer;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/t68;->OooOOO0:Llyiahf/vczjk/ow6;

    iput-object p2, p0, Llyiahf/vczjk/t68;->OooOOO:Llyiahf/vczjk/ow6;

    iput-object p3, p0, Llyiahf/vczjk/t68;->OooOOOO:Llyiahf/vczjk/ow6;

    iput p4, p0, Llyiahf/vczjk/t68;->OooOOOo:I

    iput-object p5, p0, Llyiahf/vczjk/t68;->OooOOo0:Llyiahf/vczjk/kna;

    iput-object p6, p0, Llyiahf/vczjk/t68;->OooOOo:Llyiahf/vczjk/e89;

    iput p7, p0, Llyiahf/vczjk/t68;->OooOOoo:I

    iput p8, p0, Llyiahf/vczjk/t68;->OooOo00:I

    iput-object p9, p0, Llyiahf/vczjk/t68;->OooOo0:Llyiahf/vczjk/ow6;

    iput-object p10, p0, Llyiahf/vczjk/t68;->OooOo0O:Llyiahf/vczjk/yu2;

    iput-object p11, p0, Llyiahf/vczjk/t68;->OooOo0o:Llyiahf/vczjk/ow6;

    iput-object p12, p0, Llyiahf/vczjk/t68;->OooOo:Ljava/lang/Integer;

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    check-cast p1, Llyiahf/vczjk/nw6;

    iget-object v0, p0, Llyiahf/vczjk/t68;->OooOOO0:Llyiahf/vczjk/ow6;

    const/4 v1, 0x0

    invoke-static {p1, v0, v1, v1}, Llyiahf/vczjk/nw6;->OooO0o(Llyiahf/vczjk/nw6;Llyiahf/vczjk/ow6;II)V

    iget-object v0, p0, Llyiahf/vczjk/t68;->OooOOO:Llyiahf/vczjk/ow6;

    const/4 v2, 0x0

    invoke-virtual {p1, v0, v1, v1, v2}, Llyiahf/vczjk/nw6;->OooO0o0(Llyiahf/vczjk/ow6;IIF)V

    iget-object v0, p0, Llyiahf/vczjk/t68;->OooOOOO:Llyiahf/vczjk/ow6;

    iget v3, v0, Llyiahf/vczjk/ow6;->OooOOO0:I

    iget v4, p0, Llyiahf/vczjk/t68;->OooOOOo:I

    sub-int/2addr v4, v3

    iget-object v3, p0, Llyiahf/vczjk/t68;->OooOOo:Llyiahf/vczjk/e89;

    invoke-interface {v3}, Llyiahf/vczjk/o34;->getLayoutDirection()Llyiahf/vczjk/yn4;

    move-result-object v5

    iget-object v6, p0, Llyiahf/vczjk/t68;->OooOOo0:Llyiahf/vczjk/kna;

    invoke-interface {v6, v3, v5}, Llyiahf/vczjk/kna;->OooO0O0(Llyiahf/vczjk/f62;Llyiahf/vczjk/yn4;)I

    move-result v5

    add-int/2addr v5, v4

    invoke-interface {v3}, Llyiahf/vczjk/o34;->getLayoutDirection()Llyiahf/vczjk/yn4;

    move-result-object v4

    invoke-interface {v6, v3, v4}, Llyiahf/vczjk/kna;->OooO0Oo(Llyiahf/vczjk/f62;Llyiahf/vczjk/yn4;)I

    move-result v3

    sub-int/2addr v5, v3

    div-int/lit8 v5, v5, 0x2

    iget v3, p0, Llyiahf/vczjk/t68;->OooOo00:I

    iget v4, p0, Llyiahf/vczjk/t68;->OooOOoo:I

    sub-int v3, v4, v3

    invoke-virtual {p1, v0, v5, v3, v2}, Llyiahf/vczjk/nw6;->OooO0o0(Llyiahf/vczjk/ow6;IIF)V

    iget-object v0, p0, Llyiahf/vczjk/t68;->OooOo0:Llyiahf/vczjk/ow6;

    iget v3, v0, Llyiahf/vczjk/ow6;->OooOOO:I

    sub-int v3, v4, v3

    invoke-virtual {p1, v0, v1, v3, v2}, Llyiahf/vczjk/nw6;->OooO0o0(Llyiahf/vczjk/ow6;IIF)V

    iget-object v0, p0, Llyiahf/vczjk/t68;->OooOo0O:Llyiahf/vczjk/yu2;

    if-eqz v0, :cond_0

    iget-object v1, p0, Llyiahf/vczjk/t68;->OooOo:Ljava/lang/Integer;

    invoke-static {v1}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    move-result v1

    sub-int/2addr v4, v1

    iget-object v1, p0, Llyiahf/vczjk/t68;->OooOo0o:Llyiahf/vczjk/ow6;

    iget v0, v0, Llyiahf/vczjk/yu2;->OooOOO0:I

    invoke-virtual {p1, v1, v0, v4, v2}, Llyiahf/vczjk/nw6;->OooO0o0(Llyiahf/vczjk/ow6;IIF)V

    :cond_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method

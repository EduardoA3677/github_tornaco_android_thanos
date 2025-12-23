.class public final Llyiahf/vczjk/bp4;
.super Llyiahf/vczjk/mo4;
.source "SourceFile"


# instance fields
.field public final synthetic OooO0O0:Llyiahf/vczjk/fp4;

.field public final synthetic OooO0OO:Llyiahf/vczjk/ze3;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/fp4;Llyiahf/vczjk/ze3;Ljava/lang/String;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/bp4;->OooO0O0:Llyiahf/vczjk/fp4;

    iput-object p2, p0, Llyiahf/vczjk/bp4;->OooO0OO:Llyiahf/vczjk/ze3;

    invoke-direct {p0, p3}, Llyiahf/vczjk/mo4;-><init>(Ljava/lang/String;)V

    return-void
.end method


# virtual methods
.method public final OooO0OO(Llyiahf/vczjk/nf5;Ljava/util/List;J)Llyiahf/vczjk/mf5;
    .locals 6

    iget-object v2, p0, Llyiahf/vczjk/bp4;->OooO0O0:Llyiahf/vczjk/fp4;

    invoke-interface {p1}, Llyiahf/vczjk/o34;->getLayoutDirection()Llyiahf/vczjk/yn4;

    move-result-object p2

    iget-object v0, v2, Llyiahf/vczjk/fp4;->OooOo00:Llyiahf/vczjk/zo4;

    iput-object p2, v0, Llyiahf/vczjk/zo4;->OooOOO0:Llyiahf/vczjk/yn4;

    invoke-interface {p1}, Llyiahf/vczjk/f62;->OooO0O0()F

    move-result p2

    iput p2, v0, Llyiahf/vczjk/zo4;->OooOOO:F

    invoke-interface {p1}, Llyiahf/vczjk/f62;->o000oOoO()F

    move-result p2

    iput p2, v0, Llyiahf/vczjk/zo4;->OooOOOO:F

    invoke-interface {p1}, Llyiahf/vczjk/o34;->OoooOo0()Z

    move-result p1

    iget-object p2, p0, Llyiahf/vczjk/bp4;->OooO0OO:Llyiahf/vczjk/ze3;

    const/4 v1, 0x0

    if-nez p1, :cond_0

    iget-object p1, v2, Llyiahf/vczjk/fp4;->OooOOO0:Llyiahf/vczjk/ro4;

    iget-object p1, p1, Llyiahf/vczjk/ro4;->OooOo00:Llyiahf/vczjk/ro4;

    if-eqz p1, :cond_0

    iput v1, v2, Llyiahf/vczjk/fp4;->OooOOo0:I

    new-instance p1, Llyiahf/vczjk/rk1;

    invoke-direct {p1, p3, p4}, Llyiahf/vczjk/rk1;-><init>(J)V

    iget-object p3, v2, Llyiahf/vczjk/fp4;->OooOo0:Llyiahf/vczjk/wo4;

    invoke-interface {p2, p3, p1}, Llyiahf/vczjk/ze3;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    move-object v1, p1

    check-cast v1, Llyiahf/vczjk/mf5;

    iget v3, v2, Llyiahf/vczjk/fp4;->OooOOo0:I

    new-instance v0, Llyiahf/vczjk/ap4;

    const/4 v5, 0x0

    move-object v4, v1

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/ap4;-><init>(Llyiahf/vczjk/mf5;Llyiahf/vczjk/fp4;ILlyiahf/vczjk/mf5;I)V

    return-object v0

    :cond_0
    iput v1, v2, Llyiahf/vczjk/fp4;->OooOOOo:I

    new-instance p1, Llyiahf/vczjk/rk1;

    invoke-direct {p1, p3, p4}, Llyiahf/vczjk/rk1;-><init>(J)V

    invoke-interface {p2, v0, p1}, Llyiahf/vczjk/ze3;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    move-object v1, p1

    check-cast v1, Llyiahf/vczjk/mf5;

    iget v3, v2, Llyiahf/vczjk/fp4;->OooOOOo:I

    new-instance v0, Llyiahf/vczjk/ap4;

    const/4 v5, 0x1

    move-object v4, v1

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/ap4;-><init>(Llyiahf/vczjk/mf5;Llyiahf/vczjk/fp4;ILlyiahf/vczjk/mf5;I)V

    return-object v0
.end method

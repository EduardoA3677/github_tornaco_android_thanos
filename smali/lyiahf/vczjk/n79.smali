.class public final Llyiahf/vczjk/n79;
.super Llyiahf/vczjk/m52;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ny6;
.implements Llyiahf/vczjk/c83;
.implements Llyiahf/vczjk/x83;


# instance fields
.field public OooOoo:Llyiahf/vczjk/le3;

.field public OooOooO:Z

.field public final OooOooo:Llyiahf/vczjk/nb9;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/le3;)V
    .locals 2

    invoke-direct {p0}, Llyiahf/vczjk/m52;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/n79;->OooOoo:Llyiahf/vczjk/le3;

    new-instance p1, Llyiahf/vczjk/o0000O0;

    const/4 v0, 0x7

    invoke-direct {p1, p0, v0}, Llyiahf/vczjk/o0000O0;-><init>(Ljava/lang/Object;I)V

    sget-object v0, Llyiahf/vczjk/gb9;->OooO00o:Llyiahf/vczjk/ey6;

    new-instance v0, Llyiahf/vczjk/nb9;

    const/4 v1, 0x0

    invoke-direct {v0, v1, v1, p1}, Llyiahf/vczjk/nb9;-><init>(Ljava/lang/Object;Ljava/lang/Object;Landroidx/compose/ui/input/pointer/PointerInputEventHandler;)V

    invoke-virtual {p0, v0}, Llyiahf/vczjk/m52;->o00000OO(Llyiahf/vczjk/l52;)Llyiahf/vczjk/l52;

    iput-object v0, p0, Llyiahf/vczjk/n79;->OooOooo:Llyiahf/vczjk/nb9;

    return-void
.end method


# virtual methods
.method public final OooOO0o()J
    .locals 5

    sget-object v0, Landroidx/compose/foundation/text/handwriting/OooO00o;->OooO00o:Llyiahf/vczjk/be2;

    invoke-static {p0}, Llyiahf/vczjk/yi4;->o00oO0o(Llyiahf/vczjk/l52;)Llyiahf/vczjk/ro4;

    move-result-object v1

    iget-object v1, v1, Llyiahf/vczjk/ro4;->Oooo0OO:Llyiahf/vczjk/f62;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget v2, Llyiahf/vczjk/lx9;->OooO0O0:I

    iget v2, v0, Llyiahf/vczjk/be2;->OooO00o:F

    invoke-interface {v1, v2}, Llyiahf/vczjk/f62;->o00Oo0(F)I

    move-result v2

    iget v3, v0, Llyiahf/vczjk/be2;->OooO0O0:F

    invoke-interface {v1, v3}, Llyiahf/vczjk/f62;->o00Oo0(F)I

    move-result v3

    iget v4, v0, Llyiahf/vczjk/be2;->OooO0OO:F

    invoke-interface {v1, v4}, Llyiahf/vczjk/f62;->o00Oo0(F)I

    move-result v4

    iget v0, v0, Llyiahf/vczjk/be2;->OooO0Oo:F

    invoke-interface {v1, v0}, Llyiahf/vczjk/f62;->o00Oo0(F)I

    move-result v0

    invoke-static {v2, v3, v4, v0}, Llyiahf/vczjk/xj0;->OooOo(IIII)J

    move-result-wide v0

    return-wide v0
.end method

.method public final OooOoo0()V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/n79;->OooOooo:Llyiahf/vczjk/nb9;

    invoke-virtual {v0}, Llyiahf/vczjk/nb9;->OooOoo0()V

    return-void
.end method

.method public final o00O0O(Llyiahf/vczjk/a93;)V
    .locals 0

    invoke-virtual {p1}, Llyiahf/vczjk/a93;->OooO00o()Z

    move-result p1

    iput-boolean p1, p0, Llyiahf/vczjk/n79;->OooOooO:Z

    return-void
.end method

.method public final ooOO(Llyiahf/vczjk/ey6;Llyiahf/vczjk/fy6;J)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/n79;->OooOooo:Llyiahf/vczjk/nb9;

    invoke-virtual {v0, p1, p2, p3, p4}, Llyiahf/vczjk/nb9;->ooOO(Llyiahf/vczjk/ey6;Llyiahf/vczjk/fy6;J)V

    return-void
.end method

.class public abstract Llyiahf/vczjk/xy8;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:F


# direct methods
.method static constructor <clinit>()V
    .locals 1

    invoke-static {}, Landroid/view/ViewConfiguration;->getScrollFriction()F

    move-result v0

    sput v0, Llyiahf/vczjk/xy8;->OooO00o:F

    return-void
.end method

.method public static final OooO00o(Llyiahf/vczjk/rf1;)Llyiahf/vczjk/t02;
    .locals 3

    sget-object v0, Llyiahf/vczjk/ch1;->OooO0oo:Llyiahf/vczjk/l39;

    check-cast p0, Llyiahf/vczjk/zf1;

    invoke-virtual {p0, v0}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/f62;

    invoke-interface {v0}, Llyiahf/vczjk/f62;->OooO0O0()F

    move-result v1

    invoke-virtual {p0, v1}, Llyiahf/vczjk/zf1;->OooO0Oo(F)Z

    move-result v1

    invoke-virtual {p0}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v2

    if-nez v1, :cond_0

    sget-object v1, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v2, v1, :cond_1

    :cond_0
    new-instance v1, Llyiahf/vczjk/fk7;

    invoke-direct {v1, v0}, Llyiahf/vczjk/fk7;-><init>(Llyiahf/vczjk/f62;)V

    new-instance v2, Llyiahf/vczjk/t02;

    invoke-direct {v2, v1}, Llyiahf/vczjk/t02;-><init>(Llyiahf/vczjk/fk7;)V

    invoke-virtual {p0, v2}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_1
    check-cast v2, Llyiahf/vczjk/t02;

    return-object v2
.end method

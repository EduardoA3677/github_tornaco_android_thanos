.class public abstract Llyiahf/vczjk/c45;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:Llyiahf/vczjk/jh1;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Llyiahf/vczjk/p35;

    const/4 v1, 0x4

    invoke-direct {v0, v1}, Llyiahf/vczjk/p35;-><init>(I)V

    new-instance v1, Llyiahf/vczjk/jh1;

    invoke-direct {v1, v0}, Llyiahf/vczjk/jh1;-><init>(Llyiahf/vczjk/le3;)V

    sput-object v1, Llyiahf/vczjk/c45;->OooO00o:Llyiahf/vczjk/jh1;

    return-void
.end method

.method public static OooO00o(Llyiahf/vczjk/rf1;)Llyiahf/vczjk/lha;
    .locals 3

    check-cast p0, Llyiahf/vczjk/zf1;

    sget-object v0, Llyiahf/vczjk/c45;->OooO00o:Llyiahf/vczjk/jh1;

    invoke-virtual {p0, v0}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/lha;

    const/4 v1, 0x0

    if-nez v0, :cond_0

    const v0, 0x4b1d16e9    # 1.0295017E7f

    invoke-virtual {p0, v0}, Llyiahf/vczjk/zf1;->OoooO(I)V

    sget-object v0, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->OooO0o:Llyiahf/vczjk/l39;

    invoke-virtual {p0, v0}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroid/view/View;

    invoke-static {v0}, Llyiahf/vczjk/xr6;->OooOO0O(Landroid/view/View;)Llyiahf/vczjk/lha;

    move-result-object v0

    invoke-virtual {p0, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    return-object v0

    :cond_0
    const v2, 0x4b1d128d    # 1.0293901E7f

    invoke-virtual {p0, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {p0, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    return-object v0
.end method

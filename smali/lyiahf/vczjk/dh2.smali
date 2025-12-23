.class public abstract Llyiahf/vczjk/dh2;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:F


# direct methods
.method static constructor <clinit>()V
    .locals 1

    sget-object v0, Llyiahf/vczjk/jk2;->OooO00o:Llyiahf/vczjk/cu1;

    const/16 v0, 0x10

    int-to-float v0, v0

    sput v0, Llyiahf/vczjk/dh2;->OooO00o:F

    return-void
.end method

.method public static OooO00o(Llyiahf/vczjk/rf1;)J
    .locals 2

    sget-object v0, Llyiahf/vczjk/m31;->OooO00o:Llyiahf/vczjk/l39;

    check-cast p0, Llyiahf/vczjk/zf1;

    invoke-virtual {p0, v0}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Llyiahf/vczjk/k31;

    invoke-virtual {p0}, Llyiahf/vczjk/k31;->OooO00o()J

    move-result-wide v0

    const p0, 0x3ea3d70a    # 0.32f

    invoke-static {p0, v0, v1}, Llyiahf/vczjk/n21;->OooO0O0(FJ)J

    move-result-wide v0

    return-wide v0
.end method

.class public final Llyiahf/vczjk/kx9;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO0Oo:Llyiahf/vczjk/era;


# instance fields
.field public OooO00o:F

.field public final OooO0O0:Llyiahf/vczjk/lr5;

.field public final OooO0OO:Llyiahf/vczjk/lr5;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    new-instance v0, Llyiahf/vczjk/m99;

    const/16 v1, 0xa

    const/4 v2, 0x0

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/m99;-><init>(IB)V

    new-instance v1, Llyiahf/vczjk/xm8;

    const/16 v2, 0x1d

    invoke-direct {v1, v2}, Llyiahf/vczjk/xm8;-><init>(I)V

    invoke-static {v1, v0}, Llyiahf/vczjk/vc6;->Oooo0(Llyiahf/vczjk/oe3;Llyiahf/vczjk/ze3;)Llyiahf/vczjk/era;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/kx9;->OooO0Oo:Llyiahf/vczjk/era;

    return-void
.end method

.method public constructor <init>(FFF)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput p1, p0, Llyiahf/vczjk/kx9;->OooO00o:F

    invoke-static {p3}, Landroidx/compose/runtime/OooO0o;->OooO0o(F)Llyiahf/vczjk/lr5;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/kx9;->OooO0O0:Llyiahf/vczjk/lr5;

    invoke-static {p2}, Landroidx/compose/runtime/OooO0o;->OooO0o(F)Llyiahf/vczjk/lr5;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/kx9;->OooO0OO:Llyiahf/vczjk/lr5;

    return-void
.end method


# virtual methods
.method public final OooO00o()F
    .locals 2

    iget v0, p0, Llyiahf/vczjk/kx9;->OooO00o:F

    const/4 v1, 0x0

    cmpg-float v0, v0, v1

    if-nez v0, :cond_0

    return v1

    :cond_0
    invoke-virtual {p0}, Llyiahf/vczjk/kx9;->OooO0O0()F

    move-result v0

    iget v1, p0, Llyiahf/vczjk/kx9;->OooO00o:F

    div-float/2addr v0, v1

    return v0
.end method

.method public final OooO0O0()F
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/kx9;->OooO0OO:Llyiahf/vczjk/lr5;

    check-cast v0, Llyiahf/vczjk/zv8;

    invoke-virtual {v0}, Llyiahf/vczjk/zv8;->OooOOoo()F

    move-result v0

    return v0
.end method

.method public final OooO0OO(F)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/kx9;->OooO0O0:Llyiahf/vczjk/lr5;

    check-cast v0, Llyiahf/vczjk/zv8;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/zv8;->OooOo00(F)V

    return-void
.end method

.method public final OooO0Oo(F)V
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/kx9;->OooO0OO:Llyiahf/vczjk/lr5;

    iget v1, p0, Llyiahf/vczjk/kx9;->OooO00o:F

    const/4 v2, 0x0

    invoke-static {p1, v1, v2}, Llyiahf/vczjk/vt6;->OooOOo0(FFF)F

    move-result p1

    check-cast v0, Llyiahf/vczjk/zv8;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/zv8;->OooOo00(F)V

    return-void
.end method

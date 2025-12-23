.class public final Llyiahf/vczjk/bf7;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO:Llyiahf/vczjk/ht5;

.field public final OooO00o:Llyiahf/vczjk/xr1;

.field public final OooO0O0:Llyiahf/vczjk/qs5;

.field public final OooO0OO:Llyiahf/vczjk/w62;

.field public final OooO0Oo:Llyiahf/vczjk/qs5;

.field public final OooO0o:Llyiahf/vczjk/lr5;

.field public final OooO0o0:Llyiahf/vczjk/lr5;

.field public final OooO0oO:Llyiahf/vczjk/lr5;

.field public final OooO0oo:Llyiahf/vczjk/lr5;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/xr1;Llyiahf/vczjk/qs5;FF)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/bf7;->OooO00o:Llyiahf/vczjk/xr1;

    iput-object p2, p0, Llyiahf/vczjk/bf7;->OooO0O0:Llyiahf/vczjk/qs5;

    new-instance p1, Llyiahf/vczjk/xe7;

    invoke-direct {p1, p0}, Llyiahf/vczjk/xe7;-><init>(Llyiahf/vczjk/bf7;)V

    invoke-static {p1}, Landroidx/compose/runtime/OooO0o;->OooO0Oo(Llyiahf/vczjk/le3;)Llyiahf/vczjk/w62;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/bf7;->OooO0OO:Llyiahf/vczjk/w62;

    sget-object p1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    invoke-static {p1}, Landroidx/compose/runtime/OooO0o;->OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/qs5;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/bf7;->OooO0Oo:Llyiahf/vczjk/qs5;

    const/4 p1, 0x0

    invoke-static {p1}, Landroidx/compose/runtime/OooO0o;->OooO0o(F)Llyiahf/vczjk/lr5;

    move-result-object p2

    iput-object p2, p0, Llyiahf/vczjk/bf7;->OooO0o0:Llyiahf/vczjk/lr5;

    invoke-static {p1}, Landroidx/compose/runtime/OooO0o;->OooO0o(F)Llyiahf/vczjk/lr5;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/bf7;->OooO0o:Llyiahf/vczjk/lr5;

    invoke-static {p4}, Landroidx/compose/runtime/OooO0o;->OooO0o(F)Llyiahf/vczjk/lr5;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/bf7;->OooO0oO:Llyiahf/vczjk/lr5;

    invoke-static {p3}, Landroidx/compose/runtime/OooO0o;->OooO0o(F)Llyiahf/vczjk/lr5;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/bf7;->OooO0oo:Llyiahf/vczjk/lr5;

    new-instance p1, Llyiahf/vczjk/ht5;

    invoke-direct {p1}, Llyiahf/vczjk/ht5;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/bf7;->OooO:Llyiahf/vczjk/ht5;

    return-void
.end method


# virtual methods
.method public final OooO00o()F
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/bf7;->OooO0OO:Llyiahf/vczjk/w62;

    invoke-virtual {v0}, Llyiahf/vczjk/w62;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Number;

    invoke-virtual {v0}, Ljava/lang/Number;->floatValue()F

    move-result v0

    return v0
.end method

.method public final OooO0O0()F
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/bf7;->OooO0oO:Llyiahf/vczjk/lr5;

    check-cast v0, Llyiahf/vczjk/zv8;

    invoke-virtual {v0}, Llyiahf/vczjk/zv8;->OooOOoo()F

    move-result v0

    return v0
.end method

.method public final OooO0OO()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/bf7;->OooO0Oo:Llyiahf/vczjk/qs5;

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Boolean;

    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v0

    return v0
.end method

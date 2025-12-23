.class public final Llyiahf/vczjk/jc9;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO00o:Llyiahf/vczjk/gi;

.field public final OooO0O0:Llyiahf/vczjk/ht5;

.field public final OooO0OO:Llyiahf/vczjk/qs5;

.field public final OooO0Oo:Llyiahf/vczjk/qs5;


# direct methods
.method public constructor <init>(Z)V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x0

    invoke-static {v0}, Llyiahf/vczjk/mc4;->OooO0O0(F)Llyiahf/vczjk/gi;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/jc9;->OooO00o:Llyiahf/vczjk/gi;

    new-instance v0, Llyiahf/vczjk/ht5;

    invoke-direct {v0}, Llyiahf/vczjk/ht5;-><init>()V

    iput-object v0, p0, Llyiahf/vczjk/jc9;->OooO0O0:Llyiahf/vczjk/ht5;

    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object p1

    invoke-static {p1}, Landroidx/compose/runtime/OooO0o;->OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/qs5;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/jc9;->OooO0OO:Llyiahf/vczjk/qs5;

    sget-object p1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    invoke-static {p1}, Landroidx/compose/runtime/OooO0o;->OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/qs5;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/jc9;->OooO0Oo:Llyiahf/vczjk/qs5;

    return-void
.end method


# virtual methods
.method public final OooO00o()F
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/jc9;->OooO00o:Llyiahf/vczjk/gi;

    invoke-virtual {v0}, Llyiahf/vczjk/gi;->OooO0Oo()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Number;

    invoke-virtual {v0}, Ljava/lang/Number;->floatValue()F

    move-result v0

    return v0
.end method

.method public final OooO0O0()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/jc9;->OooO0OO:Llyiahf/vczjk/qs5;

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Boolean;

    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v0

    return v0
.end method

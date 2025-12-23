.class public final Llyiahf/vczjk/u32;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/sa8;


# instance fields
.field public final OooO00o:Llyiahf/vczjk/rm4;

.field public final OooO0O0:Llyiahf/vczjk/t32;

.field public final OooO0OO:Llyiahf/vczjk/ht5;

.field public final OooO0Oo:Llyiahf/vczjk/qs5;

.field public final OooO0o:Llyiahf/vczjk/qs5;

.field public final OooO0o0:Llyiahf/vczjk/qs5;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/oe3;)V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    check-cast p1, Llyiahf/vczjk/rm4;

    iput-object p1, p0, Llyiahf/vczjk/u32;->OooO00o:Llyiahf/vczjk/rm4;

    new-instance p1, Llyiahf/vczjk/t32;

    invoke-direct {p1, p0}, Llyiahf/vczjk/t32;-><init>(Llyiahf/vczjk/u32;)V

    iput-object p1, p0, Llyiahf/vczjk/u32;->OooO0O0:Llyiahf/vczjk/t32;

    new-instance p1, Llyiahf/vczjk/ht5;

    invoke-direct {p1}, Llyiahf/vczjk/ht5;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/u32;->OooO0OO:Llyiahf/vczjk/ht5;

    sget-object p1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    invoke-static {p1}, Landroidx/compose/runtime/OooO0o;->OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/qs5;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/u32;->OooO0Oo:Llyiahf/vczjk/qs5;

    invoke-static {p1}, Landroidx/compose/runtime/OooO0o;->OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/qs5;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/u32;->OooO0o0:Llyiahf/vczjk/qs5;

    invoke-static {p1}, Landroidx/compose/runtime/OooO0o;->OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/qs5;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/u32;->OooO0o:Llyiahf/vczjk/qs5;

    return-void
.end method


# virtual methods
.method public final OooO00o()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/u32;->OooO0Oo:Llyiahf/vczjk/qs5;

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Boolean;

    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v0

    return v0
.end method

.method public final OooO0OO(Llyiahf/vczjk/at5;Llyiahf/vczjk/ze3;Llyiahf/vczjk/zo1;)Ljava/lang/Object;
    .locals 2

    new-instance v0, Llyiahf/vczjk/s32;

    const/4 v1, 0x0

    invoke-direct {v0, p0, p1, p2, v1}, Llyiahf/vczjk/s32;-><init>(Llyiahf/vczjk/u32;Llyiahf/vczjk/at5;Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)V

    invoke-static {v0, p3}, Llyiahf/vczjk/v34;->Oooo00O(Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    sget-object p2, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne p1, p2, :cond_0

    return-object p1

    :cond_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method

.method public final OooO0o0(F)F
    .locals 1

    invoke-static {p1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object p1

    iget-object v0, p0, Llyiahf/vczjk/u32;->OooO00o:Llyiahf/vczjk/rm4;

    invoke-interface {v0, p1}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/lang/Number;

    invoke-virtual {p1}, Ljava/lang/Number;->floatValue()F

    move-result p1

    return p1
.end method

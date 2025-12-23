.class public final Llyiahf/vczjk/z98;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/sa8;


# static fields
.field public static final OooO:Llyiahf/vczjk/era;


# instance fields
.field public final OooO00o:Llyiahf/vczjk/qr5;

.field public final OooO0O0:Llyiahf/vczjk/qr5;

.field public final OooO0OO:Llyiahf/vczjk/sr5;

.field public final OooO0Oo:Llyiahf/vczjk/qr5;

.field public final OooO0o:Llyiahf/vczjk/u32;

.field public OooO0o0:F

.field public final OooO0oO:Llyiahf/vczjk/w62;

.field public final OooO0oo:Llyiahf/vczjk/w62;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    sget-object v0, Llyiahf/vczjk/n68;->OooOoO:Llyiahf/vczjk/n68;

    sget-object v1, Llyiahf/vczjk/o68;->OooOo0o:Llyiahf/vczjk/o68;

    sget-object v2, Llyiahf/vczjk/l68;->OooO00o:Llyiahf/vczjk/era;

    new-instance v2, Llyiahf/vczjk/era;

    invoke-direct {v2, v0, v1}, Llyiahf/vczjk/era;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    sput-object v2, Llyiahf/vczjk/z98;->OooO:Llyiahf/vczjk/era;

    return-void
.end method

.method public constructor <init>(I)V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    invoke-static {p1}, Landroidx/compose/runtime/OooO0o;->OooO0oO(I)Llyiahf/vczjk/qr5;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/z98;->OooO00o:Llyiahf/vczjk/qr5;

    const/4 p1, 0x0

    invoke-static {p1}, Landroidx/compose/runtime/OooO0o;->OooO0oO(I)Llyiahf/vczjk/qr5;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/z98;->OooO0O0:Llyiahf/vczjk/qr5;

    new-instance p1, Llyiahf/vczjk/sr5;

    invoke-direct {p1}, Llyiahf/vczjk/sr5;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/z98;->OooO0OO:Llyiahf/vczjk/sr5;

    const p1, 0x7fffffff

    invoke-static {p1}, Landroidx/compose/runtime/OooO0o;->OooO0oO(I)Llyiahf/vczjk/qr5;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/z98;->OooO0Oo:Llyiahf/vczjk/qr5;

    new-instance p1, Llyiahf/vczjk/y98;

    invoke-direct {p1, p0}, Llyiahf/vczjk/y98;-><init>(Llyiahf/vczjk/z98;)V

    new-instance v0, Llyiahf/vczjk/u32;

    invoke-direct {v0, p1}, Llyiahf/vczjk/u32;-><init>(Llyiahf/vczjk/oe3;)V

    iput-object v0, p0, Llyiahf/vczjk/z98;->OooO0o:Llyiahf/vczjk/u32;

    new-instance p1, Llyiahf/vczjk/x98;

    invoke-direct {p1, p0}, Llyiahf/vczjk/x98;-><init>(Llyiahf/vczjk/z98;)V

    invoke-static {p1}, Landroidx/compose/runtime/OooO0o;->OooO0Oo(Llyiahf/vczjk/le3;)Llyiahf/vczjk/w62;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/z98;->OooO0oO:Llyiahf/vczjk/w62;

    new-instance p1, Llyiahf/vczjk/w98;

    invoke-direct {p1, p0}, Llyiahf/vczjk/w98;-><init>(Llyiahf/vczjk/z98;)V

    invoke-static {p1}, Landroidx/compose/runtime/OooO0o;->OooO0Oo(Llyiahf/vczjk/le3;)Llyiahf/vczjk/w62;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/z98;->OooO0oo:Llyiahf/vczjk/w62;

    return-void
.end method


# virtual methods
.method public final OooO00o()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/z98;->OooO0o:Llyiahf/vczjk/u32;

    invoke-virtual {v0}, Llyiahf/vczjk/u32;->OooO00o()Z

    move-result v0

    return v0
.end method

.method public final OooO0O0()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/z98;->OooO0oo:Llyiahf/vczjk/w62;

    invoke-virtual {v0}, Llyiahf/vczjk/w62;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Boolean;

    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v0

    return v0
.end method

.method public final OooO0OO(Llyiahf/vczjk/at5;Llyiahf/vczjk/ze3;Llyiahf/vczjk/zo1;)Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/z98;->OooO0o:Llyiahf/vczjk/u32;

    invoke-virtual {v0, p1, p2, p3}, Llyiahf/vczjk/u32;->OooO0OO(Llyiahf/vczjk/at5;Llyiahf/vczjk/ze3;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p1

    sget-object p2, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne p1, p2, :cond_0

    return-object p1

    :cond_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method

.method public final OooO0Oo()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/z98;->OooO0oO:Llyiahf/vczjk/w62;

    invoke-virtual {v0}, Llyiahf/vczjk/w62;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Boolean;

    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v0

    return v0
.end method

.method public final OooO0o()I
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/z98;->OooO00o:Llyiahf/vczjk/qr5;

    check-cast v0, Llyiahf/vczjk/bw8;

    invoke-virtual {v0}, Llyiahf/vczjk/bw8;->OooOOoo()I

    move-result v0

    return v0
.end method

.method public final OooO0o0(F)F
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/z98;->OooO0o:Llyiahf/vczjk/u32;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/u32;->OooO0o0(F)F

    move-result p1

    return p1
.end method

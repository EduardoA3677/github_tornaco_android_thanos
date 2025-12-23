.class public final Llyiahf/vczjk/pd6;
.super Llyiahf/vczjk/b23;
.source "SourceFile"


# static fields
.field public static final OooO0Oo:Llyiahf/vczjk/pd6;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    new-instance v0, Llyiahf/vczjk/pd6;

    const/4 v1, 0x0

    const/4 v2, 0x2

    const/4 v3, 0x3

    invoke-direct {v0, v3, v1, v2}, Llyiahf/vczjk/b23;-><init>(III)V

    sput-object v0, Llyiahf/vczjk/pd6;->OooO0Oo:Llyiahf/vczjk/pd6;

    return-void
.end method


# virtual methods
.method public final OooO0OO(Llyiahf/vczjk/j11;Llyiahf/vczjk/cx;Llyiahf/vczjk/os8;Llyiahf/vczjk/go7;)V
    .locals 1

    const/4 p3, 0x0

    invoke-virtual {p1, p3}, Llyiahf/vczjk/j11;->OooO0o0(I)I

    move-result p3

    const/4 p4, 0x1

    invoke-virtual {p1, p4}, Llyiahf/vczjk/j11;->OooO0o0(I)I

    move-result p4

    const/4 v0, 0x2

    invoke-virtual {p1, v0}, Llyiahf/vczjk/j11;->OooO0o0(I)I

    move-result p1

    invoke-interface {p2, p3, p4, p1}, Llyiahf/vczjk/cx;->OooO(III)V

    return-void
.end method

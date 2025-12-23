.class public final Llyiahf/vczjk/ce6;
.super Llyiahf/vczjk/b23;
.source "SourceFile"


# static fields
.field public static final OooO0Oo:Llyiahf/vczjk/ce6;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    new-instance v0, Llyiahf/vczjk/ce6;

    const/4 v1, 0x0

    const/4 v2, 0x2

    const/4 v3, 0x1

    invoke-direct {v0, v3, v1, v2}, Llyiahf/vczjk/b23;-><init>(III)V

    sput-object v0, Llyiahf/vczjk/ce6;->OooO0Oo:Llyiahf/vczjk/ce6;

    return-void
.end method


# virtual methods
.method public final OooO0OO(Llyiahf/vczjk/j11;Llyiahf/vczjk/cx;Llyiahf/vczjk/os8;Llyiahf/vczjk/go7;)V
    .locals 0

    const/4 p3, 0x0

    invoke-virtual {p1, p3}, Llyiahf/vczjk/j11;->OooO0o0(I)I

    move-result p1

    :goto_0
    if-ge p3, p1, :cond_0

    invoke-interface {p2}, Llyiahf/vczjk/cx;->OooOOO0()V

    add-int/lit8 p3, p3, 0x1

    goto :goto_0

    :cond_0
    return-void
.end method

.class public final Llyiahf/vczjk/be6;
.super Llyiahf/vczjk/b23;
.source "SourceFile"


# static fields
.field public static final OooO0Oo:Llyiahf/vczjk/be6;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    new-instance v0, Llyiahf/vczjk/be6;

    const/4 v1, 0x2

    const/4 v2, 0x1

    const/4 v3, 0x0

    invoke-direct {v0, v3, v1, v2}, Llyiahf/vczjk/b23;-><init>(III)V

    sput-object v0, Llyiahf/vczjk/be6;->OooO0Oo:Llyiahf/vczjk/be6;

    return-void
.end method


# virtual methods
.method public final OooO0OO(Llyiahf/vczjk/j11;Llyiahf/vczjk/cx;Llyiahf/vczjk/os8;Llyiahf/vczjk/go7;)V
    .locals 0

    const/4 p3, 0x0

    invoke-virtual {p1, p3}, Llyiahf/vczjk/j11;->OooO0o(I)Ljava/lang/Object;

    move-result-object p3

    const/4 p4, 0x1

    invoke-virtual {p1, p4}, Llyiahf/vczjk/j11;->OooO0o(I)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/ze3;

    invoke-interface {p2}, Llyiahf/vczjk/cx;->OooOOOO()Ljava/lang/Object;

    move-result-object p2

    invoke-interface {p1, p2, p3}, Llyiahf/vczjk/ze3;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    return-void
.end method

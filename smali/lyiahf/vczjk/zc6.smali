.class public final Llyiahf/vczjk/zc6;
.super Llyiahf/vczjk/b23;
.source "SourceFile"


# static fields
.field public static final OooO0Oo:Llyiahf/vczjk/zc6;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    new-instance v0, Llyiahf/vczjk/zc6;

    const/4 v1, 0x2

    const/4 v2, 0x1

    const/4 v3, 0x0

    invoke-direct {v0, v3, v1, v2}, Llyiahf/vczjk/b23;-><init>(III)V

    sput-object v0, Llyiahf/vczjk/zc6;->OooO0Oo:Llyiahf/vczjk/zc6;

    return-void
.end method


# virtual methods
.method public final OooO0OO(Llyiahf/vczjk/j11;Llyiahf/vczjk/cx;Llyiahf/vczjk/os8;Llyiahf/vczjk/go7;)V
    .locals 2

    const/4 v0, 0x1

    invoke-virtual {p1, v0}, Llyiahf/vczjk/j11;->OooO0o(I)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/z14;

    const/4 v1, 0x0

    if-eqz v0, :cond_0

    iget v0, v0, Llyiahf/vczjk/z14;->OooO00o:I

    goto :goto_0

    :cond_0
    move v0, v1

    :goto_0
    invoke-virtual {p1, v1}, Llyiahf/vczjk/j11;->OooO0o(I)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/ks0;

    if-lez v0, :cond_1

    new-instance v1, Llyiahf/vczjk/or3;

    invoke-direct {v1, p2, v0}, Llyiahf/vczjk/or3;-><init>(Llyiahf/vczjk/cx;I)V

    move-object p2, v1

    :cond_1
    invoke-virtual {p1, p2, p3, p4}, Llyiahf/vczjk/ks0;->OooooOO(Llyiahf/vczjk/cx;Llyiahf/vczjk/os8;Llyiahf/vczjk/go7;)V

    return-void
.end method

.class public final Llyiahf/vczjk/od2;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO00o:I

.field public final OooO0O0:I

.field public final OooO0OO:I

.field public final OooO0Oo:Llyiahf/vczjk/u34;

.field public final OooO0o0:Z


# direct methods
.method public constructor <init>(IIILlyiahf/vczjk/u34;Z)V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    invoke-static {p1}, Llyiahf/vczjk/e16;->OooOoO0(I)Z

    move-result v0

    if-eqz v0, :cond_3

    invoke-static {p2}, Llyiahf/vczjk/e16;->OooOoO0(I)Z

    move-result v0

    if-eqz v0, :cond_2

    invoke-static {p3}, Llyiahf/vczjk/e16;->OooOoO0(I)Z

    move-result v0

    if-eqz v0, :cond_1

    if-eqz p4, :cond_0

    iput p1, p0, Llyiahf/vczjk/od2;->OooO00o:I

    iput p2, p0, Llyiahf/vczjk/od2;->OooO0O0:I

    iput p3, p0, Llyiahf/vczjk/od2;->OooO0OO:I

    iput-object p4, p0, Llyiahf/vczjk/od2;->OooO0Oo:Llyiahf/vczjk/u34;

    iput-boolean p5, p0, Llyiahf/vczjk/od2;->OooO0o0:Z

    return-void

    :cond_0
    new-instance p1, Ljava/lang/NullPointerException;

    const-string p2, "format == null"

    invoke-direct {p1, p2}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    new-instance p1, Ljava/lang/IllegalArgumentException;

    const-string p2, "bogus nextOpcode"

    invoke-direct {p1, p2}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_2
    new-instance p1, Ljava/lang/IllegalArgumentException;

    const-string p2, "bogus family"

    invoke-direct {p1, p2}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_3
    new-instance p1, Ljava/lang/IllegalArgumentException;

    const-string p2, "bogus opcode"

    invoke-direct {p1, p2}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/String;
    .locals 3

    iget v0, p0, Llyiahf/vczjk/od2;->OooO00o:I

    add-int/lit8 v1, v0, 0x1

    :try_start_0
    sget-object v2, Llyiahf/vczjk/uc6;->OooO00o:[Llyiahf/vczjk/tc6;

    aget-object v1, v2, v1
    :try_end_0
    .catch Ljava/lang/ArrayIndexOutOfBoundsException; {:try_start_0 .. :try_end_0} :catch_0

    if-eqz v1, :cond_0

    iget-object v0, v1, Llyiahf/vczjk/tc6;->OooO0OO:Ljava/lang/String;

    return-object v0

    :catch_0
    :cond_0
    new-instance v1, Ljava/lang/IllegalArgumentException;

    int-to-char v2, v0

    if-ne v0, v2, :cond_1

    invoke-static {v0}, Llyiahf/vczjk/u34;->Oooooo0(I)Ljava/lang/String;

    move-result-object v0

    goto :goto_0

    :cond_1
    invoke-static {v0}, Llyiahf/vczjk/u34;->Oooooo(I)Ljava/lang/String;

    move-result-object v0

    :goto_0
    const-string v2, "bogus opcode: "

    invoke-virtual {v2, v0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    invoke-direct {v1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v1
.end method

.method public final toString()Ljava/lang/String;
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/od2;->OooO00o()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method

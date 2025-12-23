.class public abstract Llyiahf/vczjk/o76;
.super Ljava/lang/Object;
.source "SourceFile"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "<T:",
        "Ljava/lang/Object;",
        ">",
        "Ljava/lang/Object;"
    }
.end annotation


# direct methods
.method public static OooO00o(Ljava/lang/Iterable;)Llyiahf/vczjk/o76;
    .locals 2

    const-string v0, "source is null"

    invoke-static {p0, v0}, Llyiahf/vczjk/nqa;->Oooo0o0(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v0, Llyiahf/vczjk/ao0;

    const/4 v1, 0x2

    invoke-direct {v0, p0, v1}, Llyiahf/vczjk/ao0;-><init>(Ljava/lang/Object;I)V

    return-object v0
.end method


# virtual methods
.method public final OooO0O0(Llyiahf/vczjk/i88;)Llyiahf/vczjk/c86;
    .locals 2

    sget v0, Llyiahf/vczjk/z73;->OooO00o:I

    const-string v1, "scheduler is null"

    invoke-static {p1, v1}, Llyiahf/vczjk/nqa;->Oooo0o0(Ljava/lang/Object;Ljava/lang/String;)V

    if-lez v0, :cond_0

    new-instance v1, Llyiahf/vczjk/c86;

    invoke-direct {v1, p0, p1, v0}, Llyiahf/vczjk/c86;-><init>(Llyiahf/vczjk/o76;Llyiahf/vczjk/i88;I)V

    return-object v1

    :cond_0
    new-instance p1, Ljava/lang/IllegalArgumentException;

    const-string v1, "bufferSize > 0 required but it was "

    invoke-static {v0, v1}, Llyiahf/vczjk/ii5;->OooO0o0(ILjava/lang/String;)Ljava/lang/String;

    move-result-object v0

    invoke-direct {p1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public final OooO0OO(Llyiahf/vczjk/nl1;Llyiahf/vczjk/nl1;Llyiahf/vczjk/o0oo0000;)Llyiahf/vczjk/sm4;
    .locals 1

    const-string v0, "onNext is null"

    invoke-static {p1, v0}, Llyiahf/vczjk/nqa;->Oooo0o0(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "onError is null"

    invoke-static {p2, v0}, Llyiahf/vczjk/nqa;->Oooo0o0(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v0, Llyiahf/vczjk/sm4;

    invoke-direct {v0, p1, p2, p3}, Llyiahf/vczjk/sm4;-><init>(Llyiahf/vczjk/nl1;Llyiahf/vczjk/nl1;Llyiahf/vczjk/o0oo0000;)V

    invoke-virtual {p0, v0}, Llyiahf/vczjk/o76;->OooO0Oo(Llyiahf/vczjk/j86;)V

    return-object v0
.end method

.method public final OooO0Oo(Llyiahf/vczjk/j86;)V
    .locals 2

    :try_start_0
    invoke-virtual {p0, p1}, Llyiahf/vczjk/o76;->OooO0o0(Llyiahf/vczjk/j86;)V
    :try_end_0
    .catch Ljava/lang/NullPointerException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    return-void

    :catchall_0
    move-exception p1

    invoke-static {p1}, Llyiahf/vczjk/vc6;->Oooo(Ljava/lang/Throwable;)V

    invoke-static {p1}, Llyiahf/vczjk/qu6;->OooOOOo(Ljava/lang/Throwable;)V

    new-instance v0, Ljava/lang/NullPointerException;

    const-string v1, "Actually not, but can\'t throw other exceptions due to RS"

    invoke-direct {v0, v1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0, p1}, Ljava/lang/Throwable;->initCause(Ljava/lang/Throwable;)Ljava/lang/Throwable;

    throw v0

    :catch_0
    move-exception p1

    throw p1
.end method

.method public final OooO0o(Llyiahf/vczjk/i88;)Llyiahf/vczjk/u76;
    .locals 2

    const-string v0, "scheduler is null"

    invoke-static {p1, v0}, Llyiahf/vczjk/nqa;->Oooo0o0(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v0, Llyiahf/vczjk/u76;

    const/4 v1, 0x2

    invoke-direct {v0, p0, p1, v1}, Llyiahf/vczjk/u76;-><init>(Llyiahf/vczjk/o76;Ljava/lang/Object;I)V

    return-object v0
.end method

.method public abstract OooO0o0(Llyiahf/vczjk/j86;)V
.end method

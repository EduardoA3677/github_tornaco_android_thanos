.class public final Llyiahf/vczjk/bf1;
.super Llyiahf/vczjk/w;
.source "SourceFile"


# virtual methods
.method public final OooO0O0(ILlyiahf/vczjk/m;Ljava/lang/Object;)V
    .locals 0

    new-instance p1, Ljava/lang/IllegalStateException;

    const-string p2, "Calling launch() is not supported in Preview"

    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

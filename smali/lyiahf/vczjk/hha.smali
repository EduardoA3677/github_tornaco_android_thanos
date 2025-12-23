.class public interface abstract Llyiahf/vczjk/hha;
.super Ljava/lang/Object;
.source "SourceFile"


# virtual methods
.method public OooO00o(Ljava/lang/Class;)Llyiahf/vczjk/dha;
    .locals 1

    new-instance p1, Ljava/lang/UnsupportedOperationException;

    const-string v0, "`Factory.create(String, CreationExtras)` is not implemented. You may need to override the method and provide a custom implementation. Note that using `Factory.create(String)` is not supported and considered an error."

    invoke-direct {p1, v0}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public OooO0O0(Llyiahf/vczjk/gf4;Llyiahf/vczjk/ir5;)Llyiahf/vczjk/dha;
    .locals 1

    const-string v0, "modelClass"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {p1}, Llyiahf/vczjk/rs;->Oooo00O(Llyiahf/vczjk/gf4;)Ljava/lang/Class;

    move-result-object p1

    invoke-interface {p0, p1, p2}, Llyiahf/vczjk/hha;->OooO0OO(Ljava/lang/Class;Llyiahf/vczjk/ir5;)Llyiahf/vczjk/dha;

    move-result-object p1

    return-object p1
.end method

.method public OooO0OO(Ljava/lang/Class;Llyiahf/vczjk/ir5;)Llyiahf/vczjk/dha;
    .locals 0

    invoke-interface {p0, p1}, Llyiahf/vczjk/hha;->OooO00o(Ljava/lang/Class;)Llyiahf/vczjk/dha;

    move-result-object p1

    return-object p1
.end method

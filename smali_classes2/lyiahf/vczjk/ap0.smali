.class public final Llyiahf/vczjk/ap0;
.super Llyiahf/vczjk/cp0;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/rg0;


# virtual methods
.method public final OooO0Oo([Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    const-string v0, "args"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p0, p1}, Llyiahf/vczjk/cp0;->OooO0o0([Ljava/lang/Object;)V

    iget-object v0, p0, Llyiahf/vczjk/jp0;->OooO00o:Ljava/lang/reflect/Member;

    check-cast v0, Ljava/lang/reflect/Field;

    const/4 v1, 0x0

    invoke-static {p1}, Llyiahf/vczjk/sy;->o00000o0([Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    invoke-virtual {v0, v1, p1}, Ljava/lang/reflect/Field;->set(Ljava/lang/Object;Ljava/lang/Object;)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method

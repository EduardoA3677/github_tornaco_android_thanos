.class public final Llyiahf/vczjk/z49;
.super Llyiahf/vczjk/b59;
.source "SourceFile"


# instance fields
.field protected final _values:Llyiahf/vczjk/aq2;


# direct methods
.method public constructor <init>(Ljava/lang/Class;Llyiahf/vczjk/aq2;)V
    .locals 1

    const/4 v0, 0x0

    invoke-direct {p0, v0, p1}, Llyiahf/vczjk/b59;-><init>(ILjava/lang/Class;)V

    iput-object p2, p0, Llyiahf/vczjk/z49;->_values:Llyiahf/vczjk/aq2;

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V
    .locals 1

    sget-object v0, Llyiahf/vczjk/ig8;->OooOoO0:Llyiahf/vczjk/ig8;

    invoke-virtual {p3, v0}, Llyiahf/vczjk/tg8;->o0000Ooo(Llyiahf/vczjk/ig8;)Z

    move-result v0

    if-eqz v0, :cond_0

    invoke-virtual {p1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-virtual {p2, p1}, Llyiahf/vczjk/u94;->o0000Ooo(Ljava/lang/String;)V

    return-void

    :cond_0
    check-cast p1, Ljava/lang/Enum;

    sget-object v0, Llyiahf/vczjk/ig8;->OooOoOO:Llyiahf/vczjk/ig8;

    invoke-virtual {p3, v0}, Llyiahf/vczjk/tg8;->o0000Ooo(Llyiahf/vczjk/ig8;)Z

    move-result p3

    if-eqz p3, :cond_1

    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    move-result p1

    invoke-static {p1}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    move-result-object p1

    invoke-virtual {p2, p1}, Llyiahf/vczjk/u94;->o0000Ooo(Ljava/lang/String;)V

    return-void

    :cond_1
    iget-object p3, p0, Llyiahf/vczjk/z49;->_values:Llyiahf/vczjk/aq2;

    invoke-virtual {p3, p1}, Llyiahf/vczjk/aq2;->OooO0OO(Ljava/lang/Enum;)Llyiahf/vczjk/fg8;

    move-result-object p1

    invoke-virtual {p2, p1}, Llyiahf/vczjk/u94;->o00000oO(Llyiahf/vczjk/fg8;)V

    return-void
.end method

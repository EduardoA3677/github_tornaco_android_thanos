.class public final Llyiahf/vczjk/dj;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $exit:Llyiahf/vczjk/ct2;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ct2;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/dj;->$exit:Llyiahf/vczjk/ct2;

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    check-cast p1, Llyiahf/vczjk/co2;

    check-cast p2, Llyiahf/vczjk/co2;

    sget-object v0, Llyiahf/vczjk/co2;->OooOOOO:Llyiahf/vczjk/co2;

    if-ne p1, v0, :cond_0

    if-ne p2, v0, :cond_0

    iget-object p1, p0, Llyiahf/vczjk/dj;->$exit:Llyiahf/vczjk/ct2;

    check-cast p1, Llyiahf/vczjk/dt2;

    iget-object p1, p1, Llyiahf/vczjk/dt2;->OooO0OO:Llyiahf/vczjk/fz9;

    iget-boolean p1, p1, Llyiahf/vczjk/fz9;->OooO0o0:Z

    if-nez p1, :cond_0

    const/4 p1, 0x1

    goto :goto_0

    :cond_0
    const/4 p1, 0x0

    :goto_0
    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object p1

    return-object p1
.end method

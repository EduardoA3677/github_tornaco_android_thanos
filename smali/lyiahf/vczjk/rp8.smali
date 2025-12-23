.class public final Llyiahf/vczjk/rp8;
.super Llyiahf/vczjk/e16;
.source "SourceFile"


# instance fields
.field public final OooOO0o:Llyiahf/vczjk/ie7;

.field public final OooOOO0:Llyiahf/vczjk/qs5;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ie7;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/rp8;->OooOO0o:Llyiahf/vczjk/ie7;

    const/4 p1, 0x0

    invoke-static {p1}, Landroidx/compose/runtime/OooO0o;->OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/qs5;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/rp8;->OooOOO0:Llyiahf/vczjk/qs5;

    return-void
.end method


# virtual methods
.method public final OooOOo0(Llyiahf/vczjk/ie7;)Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/rp8;->OooOO0o:Llyiahf/vczjk/ie7;

    if-ne p1, v0, :cond_0

    const/4 p1, 0x1

    return p1

    :cond_0
    const/4 p1, 0x0

    return p1
.end method

.method public final OooOo00(Llyiahf/vczjk/ie7;)Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/rp8;->OooOO0o:Llyiahf/vczjk/ie7;

    if-ne p1, v0, :cond_0

    goto :goto_0

    :cond_0
    const-string p1, "Check failed."

    invoke-static {p1}, Llyiahf/vczjk/pz3;->OooO0O0(Ljava/lang/String;)V

    :goto_0
    iget-object p1, p0, Llyiahf/vczjk/rp8;->OooOOO0:Llyiahf/vczjk/qs5;

    check-cast p1, Llyiahf/vczjk/fw8;

    invoke-virtual {p1}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object p1

    if-nez p1, :cond_1

    const/4 p1, 0x0

    :cond_1
    return-object p1
.end method

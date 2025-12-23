.class public final Llyiahf/vczjk/wj0;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/un;


# instance fields
.field public final OooO00o:Llyiahf/vczjk/hk4;

.field public final OooO0O0:Llyiahf/vczjk/hc3;

.field public final OooO0OO:Ljava/util/Map;

.field public final OooO0Oo:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/hk4;Llyiahf/vczjk/hc3;Ljava/util/Map;)V
    .locals 1

    const-string v0, "builtIns"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "fqName"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/wj0;->OooO00o:Llyiahf/vczjk/hk4;

    iput-object p2, p0, Llyiahf/vczjk/wj0;->OooO0O0:Llyiahf/vczjk/hc3;

    iput-object p3, p0, Llyiahf/vczjk/wj0;->OooO0OO:Ljava/util/Map;

    sget-object p1, Llyiahf/vczjk/ww4;->OooOOO0:Llyiahf/vczjk/ww4;

    new-instance p2, Llyiahf/vczjk/o0oOOo;

    const/4 p3, 0x4

    invoke-direct {p2, p0, p3}, Llyiahf/vczjk/o0oOOo;-><init>(Ljava/lang/Object;I)V

    invoke-static {p1, p2}, Llyiahf/vczjk/jp8;->Oooo00o(Llyiahf/vczjk/ww4;Llyiahf/vczjk/le3;)Llyiahf/vczjk/kp4;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/wj0;->OooO0Oo:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final OooO()Ljava/util/Map;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/wj0;->OooO0OO:Ljava/util/Map;

    return-object v0
.end method

.method public final OooO0oO()Llyiahf/vczjk/sx8;
    .locals 1

    sget-object v0, Llyiahf/vczjk/sx8;->OooOO0O:Llyiahf/vczjk/up3;

    return-object v0
.end method

.method public final OooO0oo()Llyiahf/vczjk/hc3;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/wj0;->OooO0O0:Llyiahf/vczjk/hc3;

    return-object v0
.end method

.method public final getType()Llyiahf/vczjk/uk4;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/wj0;->OooO0Oo:Ljava/lang/Object;

    invoke-interface {v0}, Llyiahf/vczjk/kp4;->getValue()Ljava/lang/Object;

    move-result-object v0

    const-string v1, "getValue(...)"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v0, Llyiahf/vczjk/uk4;

    return-object v0
.end method

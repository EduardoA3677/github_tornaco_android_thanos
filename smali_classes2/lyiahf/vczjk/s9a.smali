.class public final Llyiahf/vczjk/s9a;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/kp4;
.implements Ljava/io/Serializable;


# instance fields
.field private _value:Ljava/lang/Object;

.field private initializer:Llyiahf/vczjk/le3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/le3;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/le3;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/s9a;->initializer:Llyiahf/vczjk/le3;

    sget-object p1, Llyiahf/vczjk/ws7;->OooOOoo:Llyiahf/vczjk/ws7;

    iput-object p1, p0, Llyiahf/vczjk/s9a;->_value:Ljava/lang/Object;

    return-void
.end method

.method private final writeReplace()Ljava/lang/Object;
    .locals 2

    new-instance v0, Llyiahf/vczjk/kz3;

    invoke-virtual {p0}, Llyiahf/vczjk/s9a;->getValue()Ljava/lang/Object;

    move-result-object v1

    invoke-direct {v0, v1}, Llyiahf/vczjk/kz3;-><init>(Ljava/lang/Object;)V

    return-object v0
.end method


# virtual methods
.method public final getValue()Ljava/lang/Object;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/s9a;->_value:Ljava/lang/Object;

    sget-object v1, Llyiahf/vczjk/ws7;->OooOOoo:Llyiahf/vczjk/ws7;

    if-ne v0, v1, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/s9a;->initializer:Llyiahf/vczjk/le3;

    invoke-static {v0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-interface {v0}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/s9a;->_value:Ljava/lang/Object;

    const/4 v0, 0x0

    iput-object v0, p0, Llyiahf/vczjk/s9a;->initializer:Llyiahf/vczjk/le3;

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/s9a;->_value:Ljava/lang/Object;

    return-object v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/s9a;->_value:Ljava/lang/Object;

    sget-object v1, Llyiahf/vczjk/ws7;->OooOOoo:Llyiahf/vczjk/ws7;

    if-eq v0, v1, :cond_0

    invoke-virtual {p0}, Llyiahf/vczjk/s9a;->getValue()Ljava/lang/Object;

    move-result-object v0

    invoke-static {v0}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v0

    return-object v0

    :cond_0
    const-string v0, "Lazy value not initialized yet."

    return-object v0
.end method

.class public abstract Llyiahf/vczjk/a69;
.super Llyiahf/vczjk/ib4;
.source "SourceFile"


# static fields
.field static final serialVersionUID:J = 0x1L


# instance fields
.field public transient OooOOO0:Llyiahf/vczjk/eb4;

.field protected _requestPayload:Llyiahf/vczjk/jr7;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/eb4;Ljava/lang/String;)V
    .locals 2

    const/4 v0, 0x0

    if-nez p1, :cond_0

    move-object v1, v0

    goto :goto_0

    :cond_0
    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->OoooOO0()Llyiahf/vczjk/ia4;

    move-result-object v1

    :goto_0
    invoke-direct {p0, p2, v1, v0}, Llyiahf/vczjk/ib4;-><init>(Ljava/lang/String;Llyiahf/vczjk/ia4;Ljava/lang/Throwable;)V

    iput-object p1, p0, Llyiahf/vczjk/a69;->OooOOO0:Llyiahf/vczjk/eb4;

    return-void
.end method


# virtual methods
.method public bridge synthetic OooO0OO()Ljava/lang/Object;
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/a69;->OooO0Oo()Llyiahf/vczjk/eb4;

    move-result-object v0

    return-object v0
.end method

.method public OooO0Oo()Llyiahf/vczjk/eb4;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/a69;->OooOOO0:Llyiahf/vczjk/eb4;

    return-object v0
.end method

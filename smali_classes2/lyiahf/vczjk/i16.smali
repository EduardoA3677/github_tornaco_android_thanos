.class public abstract Llyiahf/vczjk/i16;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public OooO00o:Llyiahf/vczjk/ye9;

.field public final OooO0O0:Llyiahf/vczjk/mc5;

.field public OooO0OO:Llyiahf/vczjk/mc5;

.field public OooO0Oo:Ljava/lang/Class;

.field public OooO0o:Z

.field public OooO0o0:Z

.field public OooO0oO:Ljava/lang/Boolean;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ye9;Llyiahf/vczjk/mc5;Llyiahf/vczjk/mc5;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    if-eqz p1, :cond_0

    iput-object p1, p0, Llyiahf/vczjk/i16;->OooO00o:Llyiahf/vczjk/ye9;

    iput-object p2, p0, Llyiahf/vczjk/i16;->OooO0O0:Llyiahf/vczjk/mc5;

    iput-object p3, p0, Llyiahf/vczjk/i16;->OooO0OO:Llyiahf/vczjk/mc5;

    const-class p1, Ljava/lang/Object;

    iput-object p1, p0, Llyiahf/vczjk/i16;->OooO0Oo:Ljava/lang/Class;

    const/4 p1, 0x0

    iput-boolean p1, p0, Llyiahf/vczjk/i16;->OooO0o0:Z

    const/4 p1, 0x1

    iput-boolean p1, p0, Llyiahf/vczjk/i16;->OooO0o:Z

    const/4 p1, 0x0

    iput-object p1, p0, Llyiahf/vczjk/i16;->OooO0oO:Ljava/lang/Boolean;

    return-void

    :cond_0
    new-instance p1, Ljava/lang/NullPointerException;

    const-string p2, "tag in a Node is required."

    invoke-direct {p1, p2}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    throw p1
.end method


# virtual methods
.method public abstract OooO00o()Llyiahf/vczjk/y16;
.end method

.method public final OooO0O0(Ljava/lang/Class;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/i16;->OooO0Oo:Ljava/lang/Class;

    invoke-virtual {p1, v0}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result v0

    if-nez v0, :cond_0

    iput-object p1, p0, Llyiahf/vczjk/i16;->OooO0Oo:Ljava/lang/Class;

    :cond_0
    return-void
.end method

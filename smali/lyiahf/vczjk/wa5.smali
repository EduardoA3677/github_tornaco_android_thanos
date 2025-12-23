.class public final Llyiahf/vczjk/wa5;
.super Llyiahf/vczjk/p;
.source "SourceFile"


# instance fields
.field public final OooO00o:Llyiahf/vczjk/q;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/q;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/wa5;->OooO00o:Llyiahf/vczjk/q;

    return-void
.end method


# virtual methods
.method public final OooO00o(Ljava/lang/Object;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/wa5;->OooO00o:Llyiahf/vczjk/q;

    iget-object v0, v0, Llyiahf/vczjk/q;->OooO00o:Llyiahf/vczjk/v;

    if-eqz v0, :cond_0

    invoke-virtual {v0, p1}, Llyiahf/vczjk/v;->OooO00o(Ljava/lang/Object;)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    goto :goto_0

    :cond_0
    const/4 p1, 0x0

    :goto_0
    if-eqz p1, :cond_1

    return-void

    :cond_1
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "Launcher has not been initialized"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

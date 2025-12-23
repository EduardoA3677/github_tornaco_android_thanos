.class public final Llyiahf/vczjk/u93;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO00o:Llyiahf/vczjk/jna;

.field public final OooO0O0:Ljava/util/concurrent/Executor;

.field public OooO0OO:Llyiahf/vczjk/r09;

.field public OooO0Oo:Llyiahf/vczjk/fk7;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/jna;Ljava/util/concurrent/Executor;)V
    .locals 1

    const-string v0, "executor"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/u93;->OooO00o:Llyiahf/vczjk/jna;

    iput-object p2, p0, Llyiahf/vczjk/u93;->OooO0O0:Ljava/util/concurrent/Executor;

    return-void
.end method

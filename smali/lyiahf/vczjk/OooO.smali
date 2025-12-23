.class public final Llyiahf/vczjk/OooO;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/u22;


# instance fields
.field public final synthetic OooOOO0:Llyiahf/vczjk/yp0;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/yp0;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/OooO;->OooOOO0:Llyiahf/vczjk/yp0;

    return-void
.end method


# virtual methods
.method public final onStart(Llyiahf/vczjk/uy4;)V
    .locals 1

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    iget-object v0, p0, Llyiahf/vczjk/OooO;->OooOOO0:Llyiahf/vczjk/yp0;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/yp0;->resumeWith(Ljava/lang/Object;)V

    return-void
.end method

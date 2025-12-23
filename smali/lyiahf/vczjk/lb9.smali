.class public final Llyiahf/vczjk/lb9;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $handlerCoroutine:Llyiahf/vczjk/kb9;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/kb9;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/kb9;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/lb9;->$handlerCoroutine:Llyiahf/vczjk/kb9;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    check-cast p1, Ljava/lang/Throwable;

    iget-object v0, p0, Llyiahf/vczjk/lb9;->$handlerCoroutine:Llyiahf/vczjk/kb9;

    iget-object v1, v0, Llyiahf/vczjk/kb9;->OooOOOO:Llyiahf/vczjk/yp0;

    if-eqz v1, :cond_0

    invoke-virtual {v1, p1}, Llyiahf/vczjk/yp0;->OooOO0o(Ljava/lang/Throwable;)Z

    :cond_0
    const/4 p1, 0x0

    iput-object p1, v0, Llyiahf/vczjk/kb9;->OooOOOO:Llyiahf/vczjk/yp0;

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method

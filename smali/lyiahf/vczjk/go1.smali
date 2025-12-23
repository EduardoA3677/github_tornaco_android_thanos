.class public final Llyiahf/vczjk/go1;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic $enabled:Z

.field final synthetic $onClick:Llyiahf/vczjk/le3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/le3;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/le3;Z)V
    .locals 0

    iput-boolean p2, p0, Llyiahf/vczjk/go1;->$enabled:Z

    iput-object p1, p0, Llyiahf/vczjk/go1;->$onClick:Llyiahf/vczjk/le3;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 1

    iget-boolean v0, p0, Llyiahf/vczjk/go1;->$enabled:Z

    if-eqz v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/go1;->$onClick:Llyiahf/vczjk/le3;

    invoke-interface {v0}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    :cond_0
    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0
.end method

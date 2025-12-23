.class public final Llyiahf/vczjk/nw8;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $readSet:Llyiahf/vczjk/ks5;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/ks5;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ks5;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/nw8;->$readSet:Llyiahf/vczjk/ks5;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    instance-of v0, p1, Llyiahf/vczjk/c39;

    if-eqz v0, :cond_0

    move-object v0, p1

    check-cast v0, Llyiahf/vczjk/c39;

    const/4 v1, 0x4

    invoke-virtual {v0, v1}, Llyiahf/vczjk/c39;->OooOOo(I)V

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/nw8;->$readSet:Llyiahf/vczjk/ks5;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/ks5;->OooO0Oo(Ljava/lang/Object;)Z

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method

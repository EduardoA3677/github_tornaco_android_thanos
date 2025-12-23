.class public final Llyiahf/vczjk/sn3;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/hha;


# static fields
.field public static final OooO0Oo:Llyiahf/vczjk/ws7;


# instance fields
.field public final OooO00o:Llyiahf/vczjk/lp4;

.field public final OooO0O0:Llyiahf/vczjk/hha;

.field public final OooO0OO:Llyiahf/vczjk/a0;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Llyiahf/vczjk/ws7;

    const/16 v1, 0x11

    invoke-direct {v0, v1}, Llyiahf/vczjk/ws7;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/sn3;->OooO0Oo:Llyiahf/vczjk/ws7;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/lp4;Llyiahf/vczjk/hha;Llyiahf/vczjk/era;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/sn3;->OooO00o:Llyiahf/vczjk/lp4;

    iput-object p2, p0, Llyiahf/vczjk/sn3;->OooO0O0:Llyiahf/vczjk/hha;

    new-instance p1, Llyiahf/vczjk/a0;

    const/4 p2, 0x1

    invoke-direct {p1, p3, p2}, Llyiahf/vczjk/a0;-><init>(Ljava/lang/Object;I)V

    iput-object p1, p0, Llyiahf/vczjk/sn3;->OooO0OO:Llyiahf/vczjk/a0;

    return-void
.end method


# virtual methods
.method public final OooO00o(Ljava/lang/Class;)Llyiahf/vczjk/dha;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/sn3;->OooO00o:Llyiahf/vczjk/lp4;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/lp4;->containsKey(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/sn3;->OooO0O0:Llyiahf/vczjk/hha;

    invoke-interface {v0, p1}, Llyiahf/vczjk/hha;->OooO00o(Ljava/lang/Class;)Llyiahf/vczjk/dha;

    move-result-object p1

    return-object p1

    :cond_0
    new-instance p1, Ljava/lang/UnsupportedOperationException;

    const-string v0, "`Factory.create(String, CreationExtras)` is not implemented. You may need to override the method and provide a custom implementation. Note that using `Factory.create(String)` is not supported and considered an error."

    invoke-direct {p1, v0}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public final OooO0OO(Ljava/lang/Class;Llyiahf/vczjk/ir5;)Llyiahf/vczjk/dha;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/sn3;->OooO00o:Llyiahf/vczjk/lp4;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/lp4;->containsKey(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/sn3;->OooO0OO:Llyiahf/vczjk/a0;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/a0;->OooO0OO(Ljava/lang/Class;Llyiahf/vczjk/ir5;)Llyiahf/vczjk/dha;

    move-result-object p1

    return-object p1

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/sn3;->OooO0O0:Llyiahf/vczjk/hha;

    invoke-interface {v0, p1, p2}, Llyiahf/vczjk/hha;->OooO0OO(Ljava/lang/Class;Llyiahf/vczjk/ir5;)Llyiahf/vczjk/dha;

    move-result-object p1

    return-object p1
.end method

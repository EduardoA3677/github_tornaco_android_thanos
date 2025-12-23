.class public final Llyiahf/vczjk/ba0;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $onTextLayout:Llyiahf/vczjk/oe3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/oe3;"
        }
    .end annotation
.end field

.field final synthetic $textScope:Llyiahf/vczjk/zm9;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/zm9;Llyiahf/vczjk/oe3;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ba0;->$textScope:Llyiahf/vczjk/zm9;

    iput-object p2, p0, Llyiahf/vczjk/ba0;->$onTextLayout:Llyiahf/vczjk/oe3;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    check-cast p1, Llyiahf/vczjk/mm9;

    iget-object v0, p0, Llyiahf/vczjk/ba0;->$textScope:Llyiahf/vczjk/zm9;

    if-nez v0, :cond_0

    goto :goto_0

    :cond_0
    iget-object v0, v0, Llyiahf/vczjk/zm9;->OooO00o:Llyiahf/vczjk/qs5;

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    :goto_0
    iget-object v0, p0, Llyiahf/vczjk/ba0;->$onTextLayout:Llyiahf/vczjk/oe3;

    if-eqz v0, :cond_1

    invoke-interface {v0, p1}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    :cond_1
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method

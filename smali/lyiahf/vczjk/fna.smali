.class public final Llyiahf/vczjk/fna;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic $listener:Llyiahf/vczjk/ol1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/ol1;"
        }
    .end annotation
.end field

.field final synthetic this$0:Llyiahf/vczjk/jna;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/jna;Llyiahf/vczjk/j7a;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/fna;->this$0:Llyiahf/vczjk/jna;

    iput-object p2, p0, Llyiahf/vczjk/fna;->$listener:Llyiahf/vczjk/ol1;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/fna;->this$0:Llyiahf/vczjk/jna;

    iget-object v0, v0, Llyiahf/vczjk/jna;->OooO0O0:Llyiahf/vczjk/uma;

    iget-object v1, p0, Llyiahf/vczjk/fna;->$listener:Llyiahf/vczjk/ol1;

    invoke-interface {v0, v1}, Llyiahf/vczjk/uma;->OooO0O0(Llyiahf/vczjk/ol1;)V

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0
.end method

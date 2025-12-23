.class public final Llyiahf/vczjk/nl;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/vl;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/vl;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/nl;->this$0:Llyiahf/vczjk/vl;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    check-cast p1, Llyiahf/vczjk/jl;

    iget-object v0, p0, Llyiahf/vczjk/nl;->this$0:Llyiahf/vczjk/vl;

    iget-object v0, v0, Llyiahf/vczjk/vl;->OooO00o:Llyiahf/vczjk/ga;

    invoke-virtual {v0}, Llyiahf/vczjk/ga;->get()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/e47;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object v1, p1, Llyiahf/vczjk/jl;->OooO00o:Llyiahf/vczjk/gi;

    new-instance v2, Llyiahf/vczjk/x37;

    invoke-direct {v2, p1, v0}, Llyiahf/vczjk/x37;-><init>(Llyiahf/vczjk/jl;Llyiahf/vczjk/e47;)V

    invoke-virtual {v0, v1, v2}, Llyiahf/vczjk/e47;->OooO0O0(Ljava/lang/Object;Llyiahf/vczjk/oe3;)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method

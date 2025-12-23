.class public final Llyiahf/vczjk/b89;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/d89;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/d89;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/b89;->this$0:Llyiahf/vczjk/d89;

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    check-cast p1, Llyiahf/vczjk/ro4;

    check-cast p2, Llyiahf/vczjk/ze3;

    iget-object v0, p0, Llyiahf/vczjk/b89;->this$0:Llyiahf/vczjk/d89;

    invoke-virtual {v0}, Llyiahf/vczjk/d89;->OooO00o()Llyiahf/vczjk/fp4;

    move-result-object v0

    new-instance v1, Llyiahf/vczjk/bp4;

    iget-object v2, v0, Llyiahf/vczjk/fp4;->OooOoo0:Ljava/lang/String;

    invoke-direct {v1, v0, p2, v2}, Llyiahf/vczjk/bp4;-><init>(Llyiahf/vczjk/fp4;Llyiahf/vczjk/ze3;Ljava/lang/String;)V

    invoke-virtual {p1, v1}, Llyiahf/vczjk/ro4;->Ooooo00(Llyiahf/vczjk/lf5;)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method

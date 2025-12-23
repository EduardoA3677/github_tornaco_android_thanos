.class public final synthetic Llyiahf/vczjk/kb6;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:J

.field public final synthetic OooOOO0:Z


# direct methods
.method public synthetic constructor <init>(IJZ)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-boolean p4, p0, Llyiahf/vczjk/kb6;->OooOOO0:Z

    iput-wide p2, p0, Llyiahf/vczjk/kb6;->OooOOO:J

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/4 p2, 0x1

    invoke-static {p2}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    iget-boolean v0, p0, Llyiahf/vczjk/kb6;->OooOOO0:Z

    iget-wide v1, p0, Llyiahf/vczjk/kb6;->OooOOO:J

    invoke-static {v0, v1, v2, p1, p2}, Llyiahf/vczjk/u34;->OooO0OO(ZJLlyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method

.class public final synthetic Llyiahf/vczjk/ak5;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/le3;

.field public final synthetic OooOOO0:J

.field public final synthetic OooOOOO:Z


# direct methods
.method public synthetic constructor <init>(JLlyiahf/vczjk/le3;ZI)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-wide p1, p0, Llyiahf/vczjk/ak5;->OooOOO0:J

    iput-object p3, p0, Llyiahf/vczjk/ak5;->OooOOO:Llyiahf/vczjk/le3;

    iput-boolean p4, p0, Llyiahf/vczjk/ak5;->OooOOOO:Z

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    move-object v4, p1

    check-cast v4, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/4 p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v5

    iget-object v2, p0, Llyiahf/vczjk/ak5;->OooOOO:Llyiahf/vczjk/le3;

    iget-boolean v3, p0, Llyiahf/vczjk/ak5;->OooOOOO:Z

    iget-wide v0, p0, Llyiahf/vczjk/ak5;->OooOOO0:J

    invoke-static/range {v0 .. v5}, Llyiahf/vczjk/uk5;->OooO0OO(JLlyiahf/vczjk/le3;ZLlyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
